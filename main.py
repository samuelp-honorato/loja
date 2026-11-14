import os
import re
import jwt
import html
import time
import json
import uuid
import hmac
import hashlib
import secrets
import logging
import urllib.parse
import requests
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Response, Form, UploadFile, File
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, Field
from typing import List, Optional
from supabase import create_client, Client

# ==========================================
# 1. CONFIGURAÇÕES & AMBIENTE SEGURO
# ==========================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
sec_logger = logging.getLogger("marli_security")

ENV = os.getenv("ENV", "production").lower()
IS_PROD = ENV == "production"

NOME_LOJA = os.getenv("NOME_LOJA", "Marli Essencial")
WHATSAPP_LOJA = os.getenv("WHATSAPP_LOJA", "")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "")
ADMIN_PASS_HASH = os.getenv("ADMIN_PASS_HASH", "")

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
DOMINIO_OFICIAL = os.getenv("DOMINIO_OFICIAL", "https://marli-lingerie.onrender.com").rstrip("/")
ALLOWED_ORIGINS = [DOMINIO_OFICIAL, "http://localhost:8000", "http://127.0.0.1:8000"]

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./loja.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if SUPABASE_URL and SUPABASE_KEY:
    clean_url = SUPABASE_URL.replace("/rest/v1/", "")
    supabase_client: Client = create_client(clean_url, SUPABASE_KEY)
else:
    supabase_client = None

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 2. MODELOS DO BANCO DE DADOS
# ==========================================
class CategoriaDB(Base):
    __tablename__ = "categorias_v1"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, unique=True, index=True)

class ProdutoDB(Base):
    __tablename__ = "produtos_v5"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, index=True)
    preco = Column(Float)
    preco_promocao = Column(Float, nullable=True)
    em_promocao = Column(Boolean, default=False)
    ativo = Column(Boolean, default=True)
    estoque = Column(Integer, default=1)
    imagem_url = Column(String)
    imagem_url_2 = Column(String, nullable=True)
    imagem_url_3 = Column(String, nullable=True)
    descricao = Column(String)
    tamanho = Column(String)
    cor = Column(String)
    categoria = Column(String)
    etiqueta = Column(String)

class PedidoDB(Base):
    __tablename__ = "pedidos_v5"
    id = Column(Integer, primary_key=True, index=True)
    cliente_nome = Column(String)
    telefone = Column(String)
    resumo_pedido = Column(String)
    itens_json = Column(String)
    total = Column(Float)
    status = Column(String, default="Pendente")
    data_criacao = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FUNÇÕES DE SEGURANÇA (HASH, XSS, RATE LIMIT)
# ==========================================
ALGORITHM = "HS256"
TOKENS_RESET_USADOS = set()
RATE_LIMIT_STORE = defaultdict(list)

def gerar_hash_senha(senha: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt.encode("utf-8"), 260000)
    return f"pbkdf2_sha256$260000${salt}${dk.hex()}"

def verificar_senha_admin(senha_digitada: str) -> bool:
    hash_ativo = os.getenv("ADMIN_PASS_HASH", ADMIN_PASS_HASH)
    if hash_ativo and hash_ativo.startswith("pbkdf2_sha256$"):
        try:
            _, iter_str, salt, hash_salvo = hash_ativo.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", senha_digitada.encode("utf-8"), salt.encode("utf-8"), int(iter_str))
            return hmac.compare_digest(dk.hex(), hash_salvo)
        except Exception:
            return False
    if ADMIN_PASS:
        return hmac.compare_digest(senha_digitada.encode("utf-8"), ADMIN_PASS.encode("utf-8"))
    return False

def sanitizar_texto(valor: Optional[str], max_len: int = 255) -> str:
    if not valor:
        return ""
    limpo = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(valor)).strip()
    return html.escape(limpo, quote=True)[:max_len]

def validar_url_imagem(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    u = url.strip()
    if u.startswith("https://") or u.startswith("http://"):
        return u[:500]
    raise HTTPException(status_code=400, detail="URL de imagem inválida. Use apenas links HTTP/HTTPS.")

def obter_ip_cliente(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "desconhecido"

def verificar_rate_limit(ip: str, escopo: str, limite: int, janela_segundos: int = 60):
    agora = time.time()
    chave = f"{escopo}:{ip}"
    RATE_LIMIT_STORE[chave] = [t for t in RATE_LIMIT_STORE[chave] if agora - t < janela_segundos]
    if len(RATE_LIMIT_STORE[chave]) >= limite:
        sec_logger.warning(f"[RATE_LIMIT] Bloqueio no escopo '{escopo}' para o IP {ip}")
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto e tente novamente.")
    RATE_LIMIT_STORE[chave].append(agora)

# ==========================================
# 4. INICIALIZAÇÃO DO APP & MIDDLEWARES DE DEFESA
# ==========================================
app = FastAPI(
    title=f"ERP - {NOME_LOJA}",
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.middleware("http")
async def escudo_seguranca_middleware(request: Request, call_next):
    ip = obter_ip_cliente(request)
    path = request.url.path
    metodo = request.method

    proto = request.headers.get("x-forwarded-proto", "https")
    if IS_PROD and proto == "http":
        url_https = str(request.url).replace("http://", "https://", 1)
        return RedirectResponse(url=url_https, status_code=301)

    try:
        verificar_rate_limit(ip, "global", limite=120, janela_segundos=60)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    if metodo in ("POST", "PUT", "PATCH", "DELETE") and not path.startswith("/api/webhook/whatsapp"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        origem_valida = False

        if origin and any(origin.startswith(o) for o in ALLOWED_ORIGINS):
            origem_valida = True
        elif not origin and referer and any(referer.startswith(o) for o in ALLOWED_ORIGINS):
            origem_valida = True
        elif not origin and not referer and not IS_PROD:
            origem_valida = True

        if not origem_valida:
            sec_logger.warning(f"[CSRF_BLOQUEADO] IP={ip} | Path={path} | Origin={origin} | Referer={referer}")
            return JSONResponse(status_code=403, content={"detail": "Origem da requisição não autorizada (CSRF)."})

    response = await call_next(request)

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    return response

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_admin(request: Request):
    ip = obter_ip_cliente(request)
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Não autorizado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != ADMIN_USER or payload.get("scope") != "admin_session":
            sec_logger.warning(f"[TOKEN_INVALIDO] Escopo/usuário incorreto | IP={ip}")
            raise HTTPException(status_code=401, detail="Sessão inválida")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sessão expirada")
    except Exception:
        sec_logger.warning(f"[TOKEN_ADULTERADO] Falha na decodificação JWT | IP={ip}")
        raise HTTPException(status_code=401, detail="Sessão inválida")
    return True

# ==========================================
# 5. SCHEMAS PYDANTIC COM VALIDAÇÃO RÍGIDA
# ==========================================
class CategoriaCreate(BaseModel):
    nome: str = Field(..., min_length=2, max_length=60)

class ProdutoCreate(BaseModel):
    nome: str = Field(..., min_length=2, max_length=120)
    preco: float = Field(..., gt=0, le=100000)
    estoque: int = Field(..., ge=0, le=100000)
    imagem_url: str = Field(..., min_length=8, max_length=500)
    imagem_url_2: Optional[str] = Field(None, max_length=500)
    imagem_url_3: Optional[str] = Field(None, max_length=500)
    descricao: str = Field("", max_length=1000)
    tamanho: str = Field(..., min_length=1, max_length=30)
    cor: str = Field("", max_length=40)
    categoria: str = Field(..., min_length=2, max_length=60)
    etiqueta: str = Field("", max_length=50)

class ItemCarrinho(BaseModel):
    produto_id: int = Field(..., gt=0)
    quantidade: int = Field(..., ge=1, le=100)
    nome: str = Field(..., min_length=1, max_length=120)
    preco: float = Field(..., gt=0, le=100000)
    tamanho: str = Field(..., min_length=1, max_length=30)

class PedidoCreate(BaseModel):
    cliente_nome: str = Field(..., min_length=2, max_length=100)
    telefone: str = Field(..., min_length=8, max_length=25)
    itens: List[ItemCarrinho] = Field(..., min_length=1, max_length=50)

class PromocaoUpdate(BaseModel):
    em_promocao: bool
    preco_promocao: Optional[float] = Field(None, gt=0, le=100000)

# ==========================================
# 6. ENTREGA SEGURA DE PÁGINAS E ARQUIVOS
# ==========================================
DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))

def pegar_arquivo(nome: str):
    caminho_html = os.path.join(DIRETORIO_ATUAL, "html", nome)
    if os.path.exists(caminho_html):
        return FileResponse(caminho_html)
    caminho_raiz = os.path.join(DIRETORIO_ATUAL, nome)
    if os.path.exists(caminho_raiz):
        return FileResponse(caminho_raiz)
    raise HTTPException(status_code=404, detail="Recurso não encontrado.")

@app.get("/")
def abrir_loja():
    return pegar_arquivo("index.html")

@app.get("/banner.webp")
def carregar_banner():
    return pegar_arquivo("banner.webp")

@app.get("/login")
def tela_login():
    return pegar_arquivo("login.html")

@app.get("/painel")
def abrir_painel(request: Request):
    try:
        verificar_admin(request)
        return pegar_arquivo("admin.html")
    except HTTPException:
        return RedirectResponse(url="/login")

@app.get("/express")
def abrir_painel_express(request: Request):
    try:
        verificar_admin(request)
        return pegar_arquivo("express.html")
    except HTTPException:
        return RedirectResponse(url="/login")

# ==========================================
# 7. UPLOAD RESTRITO AO ADMINISTRADOR
# ==========================================
EXTENSOES_PERMITIDAS = {"jpg", "jpeg", "png", "webp"}
MIMES_PERMITIDOS = {"image/jpeg", "image/png", "image/webp"}
TAMANHO_MAX_UPLOAD = 5 * 1024 * 1024  # 5 MB

@app.post("/api/upload")
async def upload_imagem(
    request: Request,
    file: UploadFile = File(...),
    admin: bool = Depends(verificar_admin)
):
    if not supabase_client:
        raise HTTPException(status_code=500, detail="Storage não configurado.")

    extensao = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if extensao not in EXTENSOES_PERMITIDAS or file.content_type not in MIMES_PERMITIDOS:
        sec_logger.warning(f"[UPLOAD_BLOQUEADO] Arquivo inválido ({file.filename}) | IP={obter_ip_cliente(request)}")
        raise HTTPException(status_code=400, detail="Formato inválido. Envie apenas JPG, PNG ou WEBP.")

    file_bytes = await file.read()
    if len(file_bytes) > TAMANHO_MAX_UPLOAD:
        raise HTTPException(status_code=400, detail="Imagem excede o limite de 5 MB.")

    try:
        nome_unico = f"{uuid.uuid4()}.{extensao}"
        supabase_client.storage.from_("produtos").upload(
            file=file_bytes,
            path=nome_unico,
            file_options={"content-type": file.content_type}
        )
        link_publico = supabase_client.storage.from_("produtos").get_public_url(nome_unico)
        return {"url": link_publico}
    except Exception as e:
        sec_logger.error(f"[ERRO_UPLOAD] {e}")
        raise HTTPException(status_code=500, detail="Falha ao enviar imagem.")

# ==========================================
# 8. AUTENTICAÇÃO, COOKIES SEGUROS E RESET EXPIRÁVEL
# ==========================================
@app.post("/api/login")
def fazer_login(request: Request, usuario: str = Form(...), senha: str = Form(...)):
    ip = obter_ip_cliente(request)
    verificar_rate_limit(ip, "login", limite=5, janela_segundos=60)

    usuario_ok = hmac.compare_digest(usuario.strip().encode("utf-8"), ADMIN_USER.encode("utf-8"))
    senha_ok = verificar_senha_admin(senha)

    if usuario_ok and senha_ok:
        exp = datetime.utcnow() + timedelta(hours=12)
        token = jwt.encode(
            {"sub": ADMIN_USER, "scope": "admin_session", "exp": exp},
            SECRET_KEY,
            algorithm=ALGORITHM
        )
        redirect = RedirectResponse(url="/painel", status_code=303)
        redirect.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            secure=IS_PROD,
            samesite="strict",
            max_age=43200
        )
        sec_logger.info(f"[LOGIN_SUCESSO] Admin autenticado | IP={ip}")
        return redirect

    sec_logger.warning(f"[LOGIN_FALHA] Tentativa inválida para usuário '{sanitizar_texto(usuario, 50)}' | IP={ip}")
    return RedirectResponse(url="/login?erro=1", status_code=303)

@app.get("/api/logout")
def sair():
    redirect = RedirectResponse(url="/login", status_code=303)
    redirect.delete_cookie("session_token", httponly=True, secure=IS_PROD, samesite="strict")
    return redirect

@app.post("/api/admin/gerar-hash")
def endpoint_gerar_hash(nova_senha: str = Form(..., min_length=8, max_length=128), admin: bool = Depends(verificar_admin)):
    return {
        "instrucao": "Copie o valor abaixo e cole na variável ADMIN_PASS_HASH no Render, depois apague ADMIN_PASS.",
        "ADMIN_PASS_HASH": gerar_hash_senha(nova_senha)
    }

@app.post("/api/recuperar-senha")
def solicitar_reset_senha(request: Request):
    ip = obter_ip_cliente(request)
    verificar_rate_limit(ip, "reset_senha", limite=3, janela_segundos=300)

    if not WHATSAPP_LOJA:
        raise HTTPException(status_code=400, detail="WhatsApp da loja não configurado.")

    jti = str(uuid.uuid4())
    exp = datetime.utcnow() + timedelta(minutes=15)
    token_reset = jwt.encode(
        {"sub": ADMIN_USER, "scope": "password_reset", "jti": jti, "exp": exp},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    link_reset = f"{DOMINIO_OFICIAL}/redefinir-senha?token={token_reset}"
    enviar_mensagem_whatsapp(
        WHATSAPP_LOJA,
        f"🔐 *Recuperação de Senha - {NOME_LOJA}*\n\nAcesse o link abaixo para definir uma nova senha (expira em 15 minutos e vale para 1 único uso):\n{link_reset}"
    )
    sec_logger.info(f"[RESET_SOLICITADO] Link enviado ao WhatsApp oficial | IP={ip}")
    return {"status": "Link de redefinição enviado para o WhatsApp oficial da loja (válido por 15 min)."}

@app.post("/api/redefinir-senha")
def confirmar_reset_senha(
    request: Request,
    token: str = Form(...),
    nova_senha: str = Form(..., min_length=8, max_length=128)
):
    ip = obter_ip_cliente(request)
    verificar_rate_limit(ip, "confirmar_reset", limite=5, janela_segundos=60)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if payload.get("scope") != "password_reset" or not jti or jti in TOKENS_RESET_USADOS:
            raise HTTPException(status_code=400, detail="Link inválido ou já utilizado.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Este link expirou (limite de 15 minutos).")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Token de redefinição inválido.")

    TOKENS_RESET_USADOS.add(jti)
    novo_hash = gerar_hash_senha(nova_senha)
    os.environ["ADMIN_PASS_HASH"] = novo_hash
    sec_logger.warning(f"[SENHA_ALTERADA] Senha administrativa redefinida via token temporário | IP={ip}")
    return {
        "status": "Senha atualizada com sucesso na sessão ativa.",
        "importante": "Salve este novo hash na variável ADMIN_PASS_HASH do Render para persistir após reinícios:",
        "ADMIN_PASS_HASH": novo_hash
    }

# ==========================================
# 9. ROTAS DA LOJA & ERP (COM SANITIZAÇÃO XSS)
# ==========================================
@app.get("/api/config")
def pegar_configuracoes():
    return {"whatsapp": WHATSAPP_LOJA, "nome_loja": NOME_LOJA}

@app.get("/api/categorias")
def listar_categorias(db: Session = Depends(get_db)):
    return db.query(CategoriaDB).all()

@app.post("/api/categorias")
def criar_categoria(cat: CategoriaCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    nome_limpo = sanitizar_texto(cat.nome, 60)
    existe = db.query(CategoriaDB).filter(CategoriaDB.nome == nome_limpo).first()
    if not existe:
        db.add(CategoriaDB(nome=nome_limpo))
        db.commit()
    return {"status": "ok"}

@app.delete("/api/categorias/{id}")
def excluir_categoria(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    cat = db.query(CategoriaDB).filter(CategoriaDB.id == id).first()
    if cat:
        db.delete(cat)
        db.commit()
    return {"status": "ok"}

@app.get("/api/admin/indicadores")
def obter_indicadores(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    agora = datetime.utcnow()
    pedidos = db.query(PedidoDB).all()
    fat_hoje = sum(p.total for p in pedidos if p.status == "Pago" and p.data_criacao >= datetime(agora.year, agora.month, agora.day))
    fat_mes = sum(p.total for p in pedidos if p.status == "Pago" and p.data_criacao >= datetime(agora.year, agora.month, 1))
    return {
        "faturamento_hoje": fat_hoje,
        "faturamento_mes": fat_mes,
        "total_pedidos": len(pedidos),
        "pedidos_pendentes": len([p for p in pedidos if p.status == "Pendente"])
    }

@app.get("/api/admin/pedidos")
def listar_pedidos_admin(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    return db.query(PedidoDB).order_by(PedidoDB.id.desc()).all()

@app.patch("/api/admin/pedidos/{id}/status")
def atualizar_status_pedido(id: int, status_novo: str = Form(...), db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    status_permitidos = {"Pendente", "Pago", "Cancelado"}
    if status_novo not in status_permitidos:
        raise HTTPException(status_code=400, detail="Status inválido.")

    pedido = db.query(PedidoDB).filter(PedidoDB.id == id).first()
    if pedido:
        if status_novo == "Pago" and pedido.status != "Pago":
            try:
                for item in json.loads(pedido.itens_json):
                    produto = db.query(ProdutoDB).filter(ProdutoDB.id == item["produto_id"]).first()
                    if produto:
                        produto.estoque = max(0, produto.estoque - int(item["quantidade"]))
            except Exception:
                pass
        elif pedido.status == "Pago" and status_novo != "Pago":
            try:
                for item in json.loads(pedido.itens_json):
                    produto = db.query(ProdutoDB).filter(ProdutoDB.id == item["produto_id"]).first()
                    if produto:
                        produto.estoque += int(item["quantidade"])
            except Exception:
                pass
        pedido.status = status_novo
        db.commit()
    return {"status": "sucesso"}

@app.post("/api/produtos")
def cadastrar_produto(produto: ProdutoCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    novo = ProdutoDB(
        nome=sanitizar_texto(produto.nome, 120),
        preco=produto.preco,
        estoque=produto.estoque,
        imagem_url=validar_url_imagem(produto.imagem_url),
        imagem_url_2=validar_url_imagem(produto.imagem_url_2),
        imagem_url_3=validar_url_imagem(produto.imagem_url_3),
        descricao=sanitizar_texto(produto.descricao, 1000),
        tamanho=sanitizar_texto(produto.tamanho, 30),
        cor=sanitizar_texto(produto.cor, 40),
        categoria=sanitizar_texto(produto.categoria, 60),
        etiqueta=sanitizar_texto(produto.etiqueta, 50)
    )
    db.add(novo)
    db.commit()
    return novo

@app.put("/api/produtos/{id}")
def editar_produto(id: int, produto: ProdutoCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    prod = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if not prod:
        raise HTTPException(status_code=404)
    prod.nome = sanitizar_texto(produto.nome, 120)
    prod.preco = produto.preco
    prod.estoque = produto.estoque
    prod.imagem_url = validar_url_imagem(produto.imagem_url)
    prod.imagem_url_2 = validar_url_imagem(produto.imagem_url_2)
    prod.imagem_url_3 = validar_url_imagem(produto.imagem_url_3)
    prod.descricao = sanitizar_texto(produto.descricao, 1000)
    prod.tamanho = sanitizar_texto(produto.tamanho, 30)
    prod.cor = sanitizar_texto(produto.cor, 40)
    prod.categoria = sanitizar_texto(produto.categoria, 60)
    prod.etiqueta = sanitizar_texto(produto.etiqueta, 50)
    db.commit()
    return {"status": "ok"}

@app.get("/api/produtos")
def listar_produtos(db: Session = Depends(get_db)):
    return db.query(ProdutoDB).filter(ProdutoDB.estoque > 0, ProdutoDB.ativo == True).order_by(ProdutoDB.id.desc()).all()

@app.get("/api/admin/produtos")
def listar_estoque_admin(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    return db.query(ProdutoDB).order_by(ProdutoDB.id.desc()).all()

@app.delete("/api/produtos/{id}")
def excluir_produto(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto:
        db.delete(produto)
        db.commit()
    return {"status": "ok"}

@app.patch("/api/produtos/{id}/status")
def alterar_status(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto:
        produto.ativo = not produto.ativo
        db.commit()
    return {"status": "ok"}

@app.patch("/api/admin/produtos/{id}/estoque")
def ajustar_estoque_rapido(id: int, delta: int = Form(...), db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    if delta < -100 or delta > 100 or delta == 0:
        raise HTTPException(status_code=400, detail="Ajuste de estoque inválido.")
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if not produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado.")
    produto.estoque = max(0, produto.estoque + delta)
    db.commit()
    return {"status": "ok", "estoque": produto.estoque}

@app.patch("/api/produtos/{id}/promocao")
def aplicar_promocao(id: int, promo: PromocaoUpdate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto:
        if promo.em_promocao and (not promo.preco_promocao or promo.preco_promocao >= produto.preco):
            raise HTTPException(status_code=400, detail="Preço promocional deve ser menor que o original.")
        produto.em_promocao = promo.em_promocao
        produto.preco_promocao = promo.preco_promocao
        db.commit()
    return {"status": "ok"}

@app.post("/api/comprar")
def finalizar_compra(request: Request, pedido: PedidoCreate, db: Session = Depends(get_db)):
    ip = obter_ip_cliente(request)
    verificar_rate_limit(ip, "checkout", limite=10, janela_segundos=60)

    cliente_limpo = sanitizar_texto(pedido.cliente_nome, 100)
    telefone_limpo = re.sub(r"[^0-9+\-\s()]", "", pedido.telefone)[:25]
    if len(re.sub(r"\D", "", telefone_limpo)) < 8:
        raise HTTPException(status_code=400, detail="Telefone inválido.")

    total_compra = 0.0
    resumo_itens = []
    itens_validados = []

    for item in pedido.itens:
        produto = db.query(ProdutoDB).filter(ProdutoDB.id == item.produto_id, ProdutoDB.ativo == True).first()
        if not produto or produto.estoque < item.quantidade:
            raise HTTPException(status_code=400, detail="Estoque insuficiente para um dos itens.")

        preco_real = produto.preco_promocao if (produto.em_promocao and produto.preco_promocao) else produto.preco
        total_compra += (preco_real * item.quantidade)

        referencia = f" | Ref: {produto.etiqueta}" if produto.etiqueta else ""
        tam_limpo = sanitizar_texto(item.tamanho, 30)
        resumo_itens.append(f"▪️ {item.quantidade}x {produto.nome} (Tam: {tam_limpo}{referencia}) - R$ {preco_real:.2f}")
        itens_validados.append({
            "produto_id": produto.id,
            "quantidade": item.quantidade,
            "nome": produto.nome,
            "preco": preco_real,
            "tamanho": tam_limpo
        })

    texto_resumo = "\n".join(resumo_itens)
    itens_dump = json.dumps(itens_validados)

    novo_pedido = PedidoDB(
        cliente_nome=cliente_limpo,
        telefone=telefone_limpo,
        resumo_pedido=texto_resumo,
        itens_json=itens_dump,
        total=round(total_compra, 2)
    )
    db.add(novo_pedido)
    db.commit()

    mensagem = f"🛒 *NOVO PEDIDO #{novo_pedido.id}* 🛒\n\n*Cliente:* {cliente_limpo}\n\n*Itens:*\n{texto_resumo}\n\n*Total: R$ {total_compra:.2f}*"
    return {"status": "sucesso", "whatsapp_url": f"https://wa.me/{WHATSAPP_LOJA}?text={urllib.parse.quote(mensagem)}"}

# ==========================================
# 10. WEBHOOK WHATSAPP META
# ==========================================
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID", "")

def enviar_mensagem_whatsapp(telefone_destino: str, texto: str):
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_ID:
        sec_logger.warning("[WHATSAPP] Credenciais ausentes no ambiente.")
        return

    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": telefone_destino,
        "type": "text",
        "text": {"body": texto}
    }
    requests.post(url, headers=headers, json=payload, timeout=10)

@app.get("/api/webhook/whatsapp")
async def verify_webhook(request: Request):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")

    if WHATSAPP_VERIFY_TOKEN and mode == "subscribe" and hmac.compare_digest(token or "", WHATSAPP_VERIFY_TOKEN):
        return Response(content=challenge, media_type="text/plain")
    raise HTTPException(status_code=403, detail="Token inválido")

@app.post("/api/webhook/whatsapp")
async def receive_whatsapp(request: Request):
    try:
        body = await request.json()
        entry = body.get("entry", [])[0]
        changes = entry.get("changes", [])[0]
        value = changes.get("value", {})

        if "messages" in value:
            msg = value["messages"][0]
            telefone_remetente = msg["from"]

            if msg["type"] == "text":
                texto = sanitizar_texto(msg["text"]["body"], 300)
                resposta = f"Sócio, recebi o teu comando: '{texto}'. O motor do ERP está online e pronto."
                enviar_mensagem_whatsapp(telefone_remetente, resposta)
            elif msg["type"] == "image":
                legenda = sanitizar_texto(msg.get("image", {}).get("caption", "Sem legenda"), 200)
                resposta = f"📸 Foto recebida com sucesso!\nLegenda lida: {legenda}\n\nPreparando extração de dados..."
                enviar_mensagem_whatsapp(telefone_remetente, resposta)

        return Response(content="EVENT_RECEIVED", status_code=200)
    except Exception as e:
        sec_logger.error(f"[ERRO_WEBHOOK] {e}")
        return Response(content="EVENT_RECEIVED", status_code=200)