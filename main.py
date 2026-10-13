from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from typing import List
import urllib.parse

SQLALCHEMY_DATABASE_URL = "sqlite:///./loja.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ProdutoDB(Base):
    __tablename__ = "produtos"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, index=True)
    preco = Column(Float)
    estoque = Column(Integer, default=1)
    imagem_url = Column(String) # Vai guardar a imagem convertida
    descricao = Column(String)
    tamanho = Column(String)
    cor = Column(String)

class PedidoDB(Base):
    __tablename__ = "pedidos"
    id = Column(Integer, primary_key=True, index=True)
    cliente_nome = Column(String)
    telefone = Column(String)
    resumo_pedido = Column(String)
    total = Column(Float)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Loja Clean Pro")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

class ProdutoCreate(BaseModel):
    nome: str
    preco: float
    estoque: int
    imagem_url: str
    descricao: str
    tamanho: str
    cor: str

class ItemCarrinho(BaseModel):
    produto_id: int
    quantidade: int
    nome: str
    preco: float
    tamanho: str

class PedidoCreate(BaseModel):
    cliente_nome: str
    telefone: str
    itens: List[ItemCarrinho]

@app.post("/api/produtos")
def cadastrar_produto(produto: ProdutoCreate, db: Session = Depends(get_db)):
    novo_produto = ProdutoDB(**produto.dict())
    db.add(novo_produto)
    db.commit()
    db.refresh(novo_produto)
    return novo_produto

@app.get("/api/produtos")
def listar_produtos(db: Session = Depends(get_db)):
    return db.query(ProdutoDB).filter(ProdutoDB.estoque > 0).all()

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

    MEU_NUMERO = "5511999999999" # SEU WHATSAPP AQUI
    mensagem = f"Olá! Meu nome é {pedido.cliente_nome}.\n\nGostaria de finalizar o pedido:\n- {texto_resumo}\n\n*Total: R$ {total_compra:.2f}*"
    link_whatsapp = f"https://wa.me/{MEU_NUMERO}?text={urllib.parse.quote(mensagem)}"
    return {"status": "sucesso", "whatsapp_url": link_whatsapp}

    @app.get("/")
    def abrir_loja():
        return FileResponse("index.html")

    @app.get("/painel")
    def abrir_painel():
        return FileResponse("admin.html")