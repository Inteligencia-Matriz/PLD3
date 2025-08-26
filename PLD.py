"""
v1.0 - Versão base feita pelo Valente
v1.1 - versão mais personalizada e sem a barra lateral
v1.2 - Adição de estruturas para melhorar o acesso das informações mais especificas ao invés de analisar toda a páginna da planilha - Turmas, Unidades e Disciplinas
"""


import streamlit as st
import gspread
import bcrypt
import pandas as pd
from datetime import datetime
import time
from google.oauth2.service_account import Credentials

# ------------------------------------------------------------
# Configurações e credenciais
# ------------------------------------------------------------
CREDENCIAIS_JSON = "cred.json"
SHEET_ID = '13DvmOkiPjtXIaKLwNjBRU-klOoNzR3jmw0rNUioai7Y' # Substitua pelo seu ID de planilha
ABA_USUARIOS = 'Info Professores'

# ------------------------------------------------------------
# Funções utilitárias de conexão
# ------------------------------------------------------------
@st.cache_resource
def get_sheets():
    escopo = [
        "https://spreadsheets.google.com/feeds",
        "https://www.googleapis.com/auth/drive"
    ]
    credenciais = Credentials.from_service_account_file(CREDENCIAIS_JSON, scopes=escopo)
    client = gspread.authorize(credenciais)
    sh = client.open_by_key(SHEET_ID)
    return {
        'usuarios': sh.worksheet('Info Professores'),
        'unid': sh.worksheet('Unidade+Discip'),
        'plan': sh.worksheet('Assunto+Marcacao'),
        'aulas': sh.worksheet('Aulas Dadas'),
        'planilha': sh
    }

def safe_get_all_values(ws, retries=3, delay=1):
    for i in range(retries):
        try:
            return ws.get_all_values()
        except Exception as e:
            if i < retries-1:
                time.sleep(delay)
            else:
                raise e

def safe_append_row(ws, row, retries=3, delay=1):
    for i in range(retries):
        try:
            ws.append_row(row)
            return
        except Exception as e:
            if i < retries-1:
                time.sleep(delay)
            else:
                raise e

# ------------------------------------------------------------
# Operações com usuários
# ------------------------------------------------------------
def carregar_usuarios(sheets):
    dados = safe_get_all_values(sheets['usuarios'])
    df = pd.DataFrame(dados[1:], columns=dados[0])
    usuarios = {
        row['EMAILPROFESSOR'].strip().lower(): {
            "senha": row['SENHA'] if 'SENHA' in df.columns else "",
            "matricula": row['MATRICULAPROFESSOR'] if 'MATRICULAPROFESSOR' in df.columns else "",
            "id_prof": row['ID + PROF'] if 'ID + PROF' in df.columns else ""
        }
        for _, row in df.iterrows() if row['EMAILPROFESSOR']
    }
    return usuarios, df

def salvar_usuario(sheets, email, senha_hash, df):
    ws = sheets['usuarios']
    for idx, row_email in enumerate(df['EMAILPROFESSOR']):
        if row_email.strip().lower() == email:
            ws.update_cell(idx+2, 6, senha_hash)
            break

def registrar_log_acesso(sheets, email):
    sh = sheets['planilha']
    try:
        aba_logs = sh.worksheet("logs")
    except gspread.exceptions.WorksheetNotFound:
        sh.add_worksheet(title="logs", rows="1000", cols="3")
        aba_logs = sh.worksheet("logs")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_append_row(aba_logs, [email, "LOGIN_OK", timestamp])

# ------------------------------------------------------------
# Inicialização do Streamlit
# ------------------------------------------------------------
st.set_page_config(page_title="Planejamento de Aulas", layout="wide", page_icon="🔐")

if "etapa" not in st.session_state:
    st.session_state.etapa = "email"

sheets = get_sheets()
usuarios, df_info = carregar_usuarios(sheets)

# --------------------------
# Etapas de Login
# --------------------------
if st.session_state.etapa == "email":
    st.title("🔒 Acesso ao Sistema")
    email = st.text_input("Digite seu e-mail institucional")
    if st.button("Continuar"):
        email = email.strip().lower()
        st.session_state.email = email

        if not email:
            st.error("Preencha o e-mail.")
        elif email not in usuarios:
            st.error("E-mail não autorizado.")
        elif usuarios[email]["senha"]:
            st.session_state.etapa = "login"
        else:
            st.session_state.etapa = "criar_senha"

elif st.session_state.etapa == "criar_senha":
    st.title("🔑 Crie sua senha de acesso")
    nova_senha = st.text_input("Crie sua senha", type="password")
    confirmar_senha = st.text_input("Confirme sua senha", type="password")

    if st.button("Criar acesso"):
        if not nova_senha or not confirmar_senha:
            st.error("Preencha os dois campos de senha.")
        elif nova_senha != confirmar_senha:
            st.error("As senhas não coincidem.")
        else:
            try:
                senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
                salvar_usuario(sheets, st.session_state.email, senha_hash, df_info)
                st.success("Senha criada. Faça o login.")
                st.session_state.etapa = "login"
            except Exception as e:
                st.error(f"Erro ao salvar senha: {e}")

elif st.session_state.etapa == "login":
    st.title("🔑 Digite sua senha")
    senha_digitada = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        email = st.session_state.get("email", "")
        if email in usuarios:
            senha_hash = usuarios[email]["senha"]
            try:
                if bcrypt.checkpw(senha_digitada.encode(), senha_hash.encode()):
                    st.session_state.etapa = "autenticado"
                    st.session_state.prof_email = email
                    st.session_state.prof_matricula = usuarios[email]["matricula"]
                    st.session_state.id_prof = usuarios[email]["id_prof"]
                    registrar_log_acesso(sheets, email)
                    st.success(f"Bem-vindo, {email.split('@')[0].capitalize()}!")
                    st.rerun()
                else:
                    st.error("Senha incorreta.")
            except Exception as e:
                st.error(f"Erro ao verificar senha: {e}")

# --------------------------
# Etapa: Autenticado -> Planejamento de Aulas
# --------------------------
if st.session_state.get("etapa") == "autenticado":
    
    st.title("📋 Planejamento de Aulas")

    # Carrega dados de unidades e planejamento
    df_unid = pd.DataFrame(safe_get_all_values(sheets['unid']))
    df_unid.columns = df_unid.iloc[0]
    df_unid = df_unid[1:].reset_index(drop=True)

    df_plan = pd.DataFrame(safe_get_all_values(sheets['plan']))
    df_plan.columns = df_plan.iloc[0]
    df_plan = df_plan[1:].reset_index(drop=True)

    # Normaliza colunas
    if 'SERIENORM' not in df_unid.columns:
        df_unid['SERIENORM'] = df_unid.iloc[:,5]
    if 'DISCNORM' not in df_unid.columns:
        df_unid['DISCNORM'] = df_unid.iloc[:,9]

    if 'SERIENORM' not in df_plan.columns:
        df_plan['SERIENORM'] = df_plan.iloc[:,3]
    if 'DISCNORM' not in df_plan.columns:
        df_plan['DISCNORM'] = df_plan.iloc[:,1]

    mat = st.session_state.prof_matricula
    id_prof = st.session_state.id_prof

    # Seleção de unidade, turma e disciplina
    unis = df_unid[df_unid['CHAPA/MATRICULA PROFESSOR'] == mat]['FILIAL'].unique()
    unidade = st.selectbox("Selecione sua unidade", options=unis)

    df_t = df_unid[(df_unid['CHAPA/MATRICULA PROFESSOR'] == mat) & (df_unid['FILIAL'] == unidade)]
    turmas = df_t['CODTURMA'].unique()
    turma = st.selectbox("Selecione sua turma", options=turmas)
    
    df_d = df_t[df_t['CODTURMA'] == turma]
    
    disciplinas_disponiveis = []
    for _, row in df_d.iterrows():
        disc_norm_unid = str(row['DISCNORM']).strip().lower()
        
        if not df_plan[df_plan['DISCNORM'].str.lower().str.contains(disc_norm_unid, regex=False)].empty:
            disciplinas_disponiveis.append(row['DISCIPLINA'])
    
    disciplinas = list(set(disciplinas_disponiveis))
    disciplina = st.selectbox("Selecione a disciplina", options=disciplinas if disciplinas else ["Nenhuma disciplina disponível"])

    serie_norm = df_d[df_d['DISCIPLINA'] == disciplina]['SERIENORM'].iloc[0] if disciplina and disciplina != "Nenhuma disciplina disponível" else None
    disc_norm = df_d[df_d['DISCIPLINA'] == disciplina]['DISCNORM'].iloc[0] if disciplina and disciplina != "Nenhuma disciplina disponível" else None
    
    df_filtered = pd.DataFrame()
    if serie_norm and disc_norm:
        df_filtered = df_plan[
            (df_plan['SERIENORM'] == serie_norm) & 
            (df_plan['DISCNORM'].str.lower().str.contains(disc_norm.lower(), regex=False))
        ].copy()

    if not df_filtered.empty and 'DISCIPLINA' in df_filtered.columns:
        frentes = df_filtered['DISCIPLINA'].unique()
    else:
        frentes = []
    
    frente = st.selectbox("Selecione a frente da disciplina", 
                          options=frentes if len(frentes) > 0 else ["Nenhuma frente disponível"])

    if frente and frente != "Nenhuma frente disponível" and not df_filtered.empty and 'DISCIPLINA' in df_filtered.columns:
        df_frente = df_filtered[df_filtered['DISCIPLINA'] == frente].copy()
    else:
        df_frente = pd.DataFrame()

    st.write("### Planejamento Semanal")
    if not df_frente.empty:
        colunas_planejamento = [c for c in df_frente.columns if c.upper() in ['SEMANA', 'TÓPICO', 'SUBTÓPICO']]
        
        planej = df_frente[colunas_planejamento].copy() if not df_frente.empty else pd.DataFrame()
        
        if planej.empty:
            st.warning("Nenhum dado de planejamento encontrado para os filtros selecionados.")
            st.stop()

        if 'TÓPICO' in planej.columns:
            planej = planej[planej['TÓPICO'].astype(str).str.strip() != ''].copy()
        
        # <--- MODIFICAÇÃO INÍCIO: LÓGICA DE VERIFICAÇÃO MAIS EFICIENTE E ESPECÍFICA
        
        # Inicializa colunas de controle antes de qualquer lógica
        planej['Aula Dada'] = False
        planej['Registrada'] = False

        try:
            # 1. Carrega a planilha de aulas dadas
            dados_aulas = safe_get_all_values(sheets['aulas'])
            if len(dados_aulas) > 1:
                df_aulas = pd.DataFrame(dados_aulas[1:], columns=dados_aulas[0])
                # Garante que as colunas usadas na filtragem sejam do tipo string para evitar erros
                cols_to_str = ['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico']
                for col in cols_to_str:
                    if col in df_aulas.columns:
                        df_aulas[col] = df_aulas[col].astype(str).str.strip()

                # 2. Filtra o DataFrame APENAS para o contexto atual (professor, unidade, turma, disciplina)
                aulas_no_contexto = df_aulas[
                    (df_aulas['Codigo Professor'] == str(id_prof).strip()) &
                    (df_aulas['Unidade'] == str(unidade).strip()) &
                    (df_aulas['Turma'] == str(turma).strip()) &
                    (df_aulas['Disciplina'] == str(frente).strip())
                ]

                # 3. Cria um SET com os tópicos JÁ REGISTRADOS neste contexto (muito rápido para consultar)
                if not aulas_no_contexto.empty:
                    topicos_registrados = set(aulas_no_contexto['Topico'])

                    # 4. Aplica a verificação no planejamento
                    if 'TÓPICO' in planej.columns:
                        planej['Registrada'] = planej['TÓPICO'].apply(
                            lambda topico: str(topico).strip() in topicos_registrados
                        )
                        planej['Aula Dada'] = planej['Registrada']
            else:
                # Caso não haja aulas dadas, cria um DataFrame vazio para não quebrar a lógica de salvar
                df_aulas = pd.DataFrame(columns=['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico', 'Subtopico'])

        except Exception as e:
            st.error(f"Erro ao verificar aulas já registradas: {e}")
            df_aulas = pd.DataFrame(columns=['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico', 'Subtopico'])

        # <--- MODIFICAÇÃO FIM
        
        column_config = {
            "Aula Dada": st.column_config.CheckboxColumn(
                "Aula Dada",
                help="Marque se a aula foi ministrada",
                disabled=False
            ),
            "Registrada": st.column_config.CheckboxColumn(
                "Registrada",
                help="Aula já registrada no sistema",
                disabled=True
            )
        }

        planej_edit = st.data_editor(
            planej,
            column_config=column_config,
            disabled=["Registrada"],
            hide_index=True,
            key=f"editor_{unidade}_{turma}_{disciplina}"
        )

        if st.button("Salvar aulas dadas"):
            novas_aulas = []
            for idx, row in planej_edit.iterrows():
                try:
                    if row['Aula Dada'] and not planej.at[idx, 'Registrada']:
                        topico = str(row['TÓPICO']) if 'TÓPICO' in row else ''
                        subtopico = str(row['SUBTÓPICO']) if 'SUBTÓPICO' in row else ''
                        
                        # A verificação de duplicidade agora é mais robusta, pois a coluna 'Registrada' já fez o trabalho
                        novas_aulas.append([
                            id_prof,
                            unidade,
                            turma,
                            datetime.now().strftime("%d/%m/%Y"),
                            frente,
                            topico,
                            subtopico,
                            '', ''
                        ])
                except Exception as e:
                    st.error(f"Erro ao processar linha {idx} para salvar: {e}")
                    continue
            
            if novas_aulas:
                try:
                    for aula in novas_aulas:
                        safe_append_row(sheets['aulas'], aula)
                    st.success(f"{len(novas_aulas)} aulas registradas com sucesso!")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao salvar aulas: {e}")
            else:
                st.info("Nenhuma aula nova para registrar.")
    else:
        st.info("Nenhum planejamento encontrado para esta disciplina/turma.")
else:
    st.stop()