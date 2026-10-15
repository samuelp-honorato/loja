import os
from fastapi import FastAPI, HTTPException, Depends, status, Request, Response, Form
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List
import urllib.parse

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./loja.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ProdutoDB(Base):
    __tablename__ = "produtos_v2" 
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, index=True)
    preco = Column(Float)
    estoque = Column(Integer, default=1)
    imagem_url = Column(String)
    descricao = Column(String)
    tamanho = Column(String)
    cor = Column(String)
    categoria = Column(String)
    etiqueta = Column(String)

class PedidoDB(Base):
    __tablename__ = "pedidos_v2"
    id = Column(Integer, primary_key=True, index=True)
    cliente_nome = Column(String)
    telefone = Column(String)
    resumo_pedido = Column(String)
    total = Column(Float)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Plataforma Gestão PRO")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def verificar_admin(request: Request):
    token = request.cookies.get("session_token")
    if token != "token_secreto_admin_marli":
        raise HTTPException(status_code=401, detail="Acesso Negado")
    return True

class ProdutoCreate(BaseModel):
    nome: str; preco: float; estoque: int; imagem_url: str; descricao: str; tamanho: str; cor: str; categoria: str; etiqueta: str

class ItemCarrinho(BaseModel):
    produto_id: int; quantidade: int; nome: str; preco: float; tamanho: str

class PedidoCreate(BaseModel):
    cliente_nome: str; telefone: str; itens: List[ItemCarrinho]

@app.get("/")
def abrir_loja():
    return FileResponse("index.html")

@app.get("/login")
def tela_login():
    return FileResponse("login.html")

@app.post("/api/login")
def fazer_login(response: Response, usuario: str = Form(...), senha: str = Form(...)):
    if usuario == "admmarli" and senha == "Deusbom7.":
        redirect = RedirectResponse(url="/painel", status_code=303)
        redirect.set_cookie(key="session_token", value="token_secreto_admin_marli", httponly=True)
        return redirect
    return RedirectResponse(url="/login?erro=1", status_code=303)

@app.get("/painel")
def abrir_painel(request: Request):
    token = request.cookies.get("session_token")
    if token != "token_secreto_admin_marli":
        return RedirectResponse(url="/login")
    return FileResponse("admin.html")

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
    return db.query(ProdutoDB).filter(ProdutoDB.estoque > 0).all()

@app.get("/api/admin/produtos")
def listar_estoque_admin(db: Session = Depends(get_db), admin: bool = Depends(verificar_admin)):
    return db.query(ProdutoDB).all()

@app.post("/api/comprar")
def finalizar_compra(pedido: PedidoCreate, db: Session = Depends(get_db)):
    total_compra = 0
    resumo_itens = []
    for item in pedido.itens:
        produto = db.query(ProdutoDB).filter(ProdutoDB.id == item.produto_id).first()
        if not produto or produto.estoque < item.quantidade:
            raise HTTPException(status_code=400, detail=f"Estoque insuficiente: {item.nome}")
        produto.estoque -= item.quantidade
        total_compra += (produto.preco * item.quantidade)
        resumo_itens.append(f"{item.quantidade}x {item.nome} ({item.tamanho})")
    
    texto_resumo = "\n- ".join(resumo_itens)
    novo_pedido = PedidoDB(cliente_nome=pedido.cliente_nome, telefone=pedido.telefone, resumo_pedido=texto_resumo, total=total_compra)
    db.add(novo_pedido)
    db.commit()

    MEU_NUMERO = "5511982902294" 
    mensagem = f"Olá! O meu nome é {pedido.cliente_nome}.\n\nGostaria de finalizar o pedido:\n- {texto_resumo}\n\n*Total: R$ {total_compra:.2f}*"
    link_whatsapp = f"https://wa.me/{MEU_NUMERO}?text={urllib.parse.quote(mensagem)}"
    return {"status": "sucesso", "whatsapp_url": link_whatsapp}