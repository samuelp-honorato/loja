import os
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Response, Form
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional
import urllib.parse

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./loja.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ProdutoDB(Base):
    __tablename__ = "produtos_v3"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, index=True)
    preco = Column(Float)
    preco_promocao = Column(Float, nullable=True)
    em_promocao = Column(Boolean, default=False)
    ativo = Column(Boolean, default=True) 
    estoque = Column(Integer, default=1)
    imagem_url = Column(String)
    descricao = Column(String)
    tamanho = Column(String)
    cor = Column(String)
    categoria = Column(String)
    etiqueta = Column(String)

class PedidoDB(Base):
    __tablename__ = "pedidos_v3"
    id = Column(Integer, primary_key=True, index=True)
    cliente_nome = Column(String)
    telefone = Column(String)
    resumo_pedido = Column(String)
    total = Column(Float)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Marli ERP")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

SECRET_KEY = os.getenv("SECRET_KEY", "chave_mestre_super_secreta")
ALGORITHM = "HS256"

def verificar_admin(request: Request):
    token = request.cookies.get("session_token")
    if not token: raise HTTPException(status_code=401, detail="Não autorizado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != "admin": raise HTTPException(status_code=401)
    except: raise HTTPException(status_code=401, detail="Sessão inválida")
    return True

class ProdutoCreate(BaseModel):
    nome: str; preco: float; estoque: int; imagem_url: str; descricao: str; tamanho: str; cor: str; categoria: str; etiqueta: str

class ItemCarrinho(BaseModel):
    produto_id: int; quantidade: int; nome: str; preco: float; tamanho: str

class PedidoCreate(BaseModel):
    cliente_nome: str; telefone: str; itens: List[ItemCarrinho]

class PromocaoUpdate(BaseModel):
    em_promocao: bool
    preco_promocao: Optional[float] = None

@app.get("/")
def abrir_loja(): return FileResponse("index.html")

@app.get("/login")
def tela_login(): return FileResponse("login.html")

@app.post("/api/login")
def fazer_login(response: Response, usuario: str = Form(...), senha: str = Form(...)):
    if usuario == "admin" and senha == "marli123":
        exp = datetime.utcnow() + timedelta(hours=12)
        token = jwt.encode({"sub": usuario, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)
        redirect = RedirectResponse(url="/painel", status_code=303)
        redirect.set_cookie(key="session_token", value=token, httponly=True)
        return redirect
    return RedirectResponse(url="/login?erro=1", status_code=303)

@app.get("/painel")
def abrir_painel(request: Request):
    try:
        verificar_admin(request)
        return FileResponse("admin.html")
    except HTTPException:
        return RedirectResponse(url="/login")

@app.get("/api/logout")
def sair():
    redirect = RedirectResponse(url="/login", status_code=303)
    redirect.delete_cookie("session_token")
    return redirect

@app.post("/api/produtos")
def cadastrar_produto(produto: ProdutoCreate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    novo = ProdutoDB(**produto.dict())
    db.add(novo)
    db.commit()
    return novo

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
    return {"status": "ok", "ativo": produto.ativo}

@app.patch("/api/produtos/{id}/promocao")
def aplicar_promocao(id: int, promo: PromocaoUpdate, db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    produto = db.query(ProdutoDB).filter(ProdutoDB.id == id).first()
    if produto:
        produto.em_promocao = promo.em_promocao
        produto.preco_promocao = promo.preco_promocao
        db.commit()
    return {"status": "ok"}

@app.post("/api/comprar")
def finalizar_compra(pedido: PedidoCreate, db: Session = Depends(get_db)):
    total_compra = 0; resumo_itens = []
    for item in pedido.itens:
        produto = db.query(ProdutoDB).filter(ProdutoDB.id == item.produto_id).first()
        if not produto or produto.estoque < item.quantidade:
            raise HTTPException(status_code=400, detail=f"Estoque insuficiente: {item.nome}")
        produto.estoque -= item.quantidade
        
        preco_real = produto.preco_promocao if produto.em_promocao else produto.preco
        total_compra += (preco_real * item.quantidade)
        resumo_itens.append(f"{item.quantidade}x {item.nome} ({item.tamanho}) - R$ {preco_real:.2f}")
    
    texto_resumo = "\n- ".join(resumo_itens)
    novo_pedido = PedidoDB(cliente_nome=pedido.cliente_nome, telefone=pedido.telefone, resumo_pedido=texto_resumo, total=total_compra)
    db.add(novo_pedido)
    db.commit()

    MEU_NUMERO = "5511982902294" 
    mensagem = f"Olá! Sou {pedido.cliente_nome}.\n\n*Novo Pedido:*\n- {texto_resumo}\n\n*Total: R$ {total_compra:.2f}*"
    link_whatsapp = f"https://wa.me/{MEU_NUMERO}?text={urllib.parse.quote(mensagem)}"
    return {"status": "sucesso", "whatsapp_url": link_whatsapp}