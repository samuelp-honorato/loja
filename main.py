import os
import jwt
import json
import uuid
import urllib.parse
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Response, Form, UploadFile, File
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional
from supabase import create_client, Client


NOME_LOJA = os.getenv("NOME_LOJA", "Marli Lingerie")
WHATSAPP_LOJA = os.getenv("WHATSAPP_LOJA", "5511999999999")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "marli123")
SECRET_KEY = os.getenv("SECRET_KEY", "chave_mestre_super_secreta_marli_pro")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./loja.db")
if DATABASE_URL.startswith("postgres://"): DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SUPABASE_URL = os.getenv("https://vpzzucalzgtdymlmwnec.supabase.co/rest/v1/")
SUPABASE_KEY = os.getenv("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZwenp1Y2Fsemd0ZHltbG13bmVjIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5MzMxMDE0NCwiZXhwIjoyMTA4ODg2MTQ0fQ.rWL9mFFr32Yu_A2DxSYA4UqM6ijGi9YHUCZ877xj8tQ")

if SUPABASE_URL and SUPABASE_KEY:
    supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    supabase_client = None

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
    imagem_url_2 = Column(String, nullable=True) # Foto Extra 1
    imagem_url_3 = Column(String, nullable=True) # Foto Extra 2
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

app = FastAPI(title=f"ERP - {NOME_LOJA}")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

ALGORITHM = "HS256"

def verificar_admin(request: Request):
    token = request.cookies.get("session_token")
    if not token: raise HTTPException(status_code=401, detail="Não autorizado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != ADMIN_USER: raise HTTPException(status_code=401)
    except: raise HTTPException(status_code=401, detail="Sessão inválida")
    return True

class CategoriaCreate(BaseModel): nome: str
class ProdutoCreate(BaseModel): 
    nome: str; preco: float; estoque: int; imagem_url: str; 
    imagem_url_2: Optional[str] = None; imagem_url_3: Optional[str] = None;
    descricao: str; tamanho: str; cor: str; categoria: str; etiqueta: str
class ItemCarrinho(BaseModel): produto_id: int; quantidade: int; nome: str; preco: float; tamanho: str
class PedidoCreate(BaseModel): cliente_nome: str; telefone: str; itens: List[ItemCarrinho]
class PromocaoUpdate(BaseModel): em_promocao: bool; preco_promocao: Optional[float] = None

@app.get("/")
def abrir_loja(): return FileResponse("index.html")

@app.get("/login")
def tela_login(): return FileResponse("login.html")

@app.post("/api/upload")
async def upload_imagem(file: UploadFile = File(...)):
    if not supabase_client:
        return {"erro": "Supabase não configurado"}
        
    try:
        file_bytes = await file.read()
        
        extensao = file.filename.split(".")[-1]
        nome_unico = f"{uuid.uuid4()}.{extensao}"
        
        supabase_client.storage.from_("produtos").upload(
            file=file_bytes,
            path=nome_unico,
            file_options={"content-type": file.content_type}
        )
        
        link_publico = supabase_client.storage.from_("produtos").get_public_url(nome_unico)
        
        return {"url": link_publico}
        
    except Exception as e:
        return {"erro": str(e)}

@app.post("/api/login")
def fazer_login(response: Response, usuario: str = Form(...), senha: str = Form(...)):
    if usuario == ADMIN_USER and senha == ADMIN_PASS:
        exp = datetime.utcnow() + timedelta(hours=12)
        token = jwt.encode({"sub": usuario, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)
        redirect = RedirectResponse(url="/painel", status_code=303)
        redirect.set_cookie(key="session_token", value=token, httponly=True)
        return redirect
    return RedirectResponse(url="/login?erro=1", status_code=303)

@app.get("/painel")
def abrir_painel(request: Request):
    try: verificar_admin(request); return FileResponse("admin.html")
    except HTTPException: return RedirectResponse(url="/login")

@app.get("/api/logout")
def sair():
    redirect = RedirectResponse(url="/login", status_code=303)
    redirect.delete_cookie("session_token")
    return redirect

@app.get("/api/config")
def pegar_configuracoes(): return {"whatsapp": WHATSAPP_LOJA, "nome_loja": NOME_LOJA}

@app.get("/api/categorias")
def listar_categorias(db: Session = Depends(get_db)): return db.query(CategoriaDB).all()

@app.post("/api/categorias")
def criar_categoria(cat: CategoriaCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    existe = db.query(CategoriaDB).filter(CategoriaDB.nome == cat.nome).first()
    if not existe: db.add(CategoriaDB(nome=cat.nome)); db.commit()
    return {"status": "ok"}

@app.delete("/api/categorias/{id}")
def excluir_categoria(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    cat = db.query(CategoriaDB).filter(CategoriaDB.id == id).first()
    if cat: db.delete(cat); db.commit()
    return {"status": "ok"}

@app.get("/api/admin/indicadores")
def obter_indicadores(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    agora = datetime.utcnow()
    pedidos = db.query(PedidoDB).all()
    fat_hoje = sum(p.total for p in pedidos if p.status == "Pago" and p.data_criacao >= datetime(agora.year, agora.month, agora.day))
    fat_mes = sum(p.total for p in pedidos if p.status == "Pago" and p.data_criacao >= datetime(agora.year, agora.month, 1))
    return {"faturamento_hoje": fat_hoje, "faturamento_mes": fat_mes, "total_pedidos": len(pedidos), "pedidos_pendentes": len([p for p in pedidos if p.status == "Pendente"])}

@app.get("/api/admin/pedidos")
def listar_pedidos_admin(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    return db.query(PedidoDB).order_by(PedidoDB.id.desc()).all()

@app.patch("/api/admin/pedidos/{id}/status")
def atualizar_status_pedido(id: int, status_novo: str = Form(...), db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    pedido = db.query(PedidoDB).filter(PedidoDB.id == id).first()
    if pedido:
        if status_novo == "Pago" and pedido.status != "Pago":
            try:
                for item in json.loads(pedido.itens_json):
                    produto = db.query(ProdutoDB).filter(ProdutoDB.id == item["produto_id"]).first()
                    if produto: produto.estoque -= item["quantidade"]
            except: pass
        elif pedido.status == "Pago" and status_novo != "Pago":
            try:
                for item in json.loads(pedido.itens_json):
                    produto = db.query(ProdutoDB).filter(ProdutoDB.id == item["produto_id"]).first()
                    if produto: produto.estoque += item["quantidade"]
            except: pass
        pedido.status = status_novo; db.commit()
    return {"status": "sucesso"}

@app.post("/api/produtos")
def cadastrar_produto(produto: ProdutoCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    novo = ProdutoDB(**produto.dict()); db.add(novo); db.commit(); return novo

@app.put("/api/produtos/{id}")
def editar_produto(id: int, produto: ProdutoCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    prod = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if not prod: raise HTTPException(status_code=404)
    prod.nome = produto.nome; prod.preco = produto.preco; prod.estoque = produto.estoque
    prod.imagem_url = produto.imagem_url; prod.imagem_url_2 = produto.imagem_url_2; prod.imagem_url_3 = produto.imagem_url_3
    prod.descricao = produto.descricao; prod.tamanho = produto.tamanho; prod.cor = produto.cor
    prod.categoria = produto.categoria; prod.etiqueta = produto.etiqueta
    db.commit(); return {"status": "ok"}

@app.get("/api/produtos")
def listar_produtos(db: Session = Depends(get_db)):
    return db.query(ProdutoDB).filter(ProdutoDB.estoque > 0, ProdutoDB.ativo == True).order_by(ProdutoDB.id.desc()).all()

@app.get("/api/admin/produtos")
def listar_estoque_admin(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    return db.query(ProdutoDB).order_by(ProdutoDB.id.desc()).all()

@app.delete("/api/produtos/{id}")
def excluir_produto(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto: db.delete(produto); db.commit()
    return {"status": "ok"}

@app.patch("/api/produtos/{id}/status")
def alterar_status(id: int, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto: produto.ativo = not produto.ativo; db.commit()
    return {"status": "ok"}

@app.patch("/api/produtos/{id}/promocao")
def aplicar_promocao(id: int, promo: PromocaoUpdate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto: produto.em_promocao = promo.em_promocao; produto.preco_promocao = promo.preco_promocao; db.commit()
    return {"status": "ok"}

@app.post("/api/comprar")
def finalizar_compra(pedido: PedidoCreate, db: Session = Depends(get_db)):
    total_compra = 0; resumo_itens = []
    for item in pedido.itens:
        produto = db.query(ProdutoDB).filter(ProdutoDB.id == item.produto_id).first()
        if not produto or produto.estoque < item.quantidade: raise HTTPException(status_code=400, detail="Estoque insuficiente.")
        preco_real = produto.preco_promocao if produto.em_promocao else produto.preco
        total_compra += (preco_real * item.quantidade)
        resumo_itens.append(f"{item.quantidade}x {item.nome} ({item.tamanho}) - R$ {preco_real:.2f}")
    
    texto_resumo = "\n- ".join(resumo_itens)
    itens_dump = json.dumps([i.dict() for i in pedido.itens])
    novo_pedido = PedidoDB(cliente_nome=pedido.cliente_nome, telefone=pedido.telefone, resumo_pedido=texto_resumo, itens_json=itens_dump, total=total_compra)
    db.add(novo_pedido); db.commit()
    mensagem = f"Olá! Sou {pedido.cliente_nome}.\n\n*Novo Pedido #{novo_pedido.id}:*\n- {texto_resumo}\n\n*Total: R$ {total_compra:.2f}*"
    return {"status": "sucesso", "whatsapp_url": f"https://wa.me/{WHATSAPP_LOJA}?text={urllib.parse.quote(mensagem)}"}