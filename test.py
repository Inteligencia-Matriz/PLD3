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
SHEET_ID = '13DvmOkiPjtXIaKLwNjBRU-klOoNzR3jmw0rNUioai7Y'
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
            "matricula": row['MATRICULAPROFESSOR'] if 'MATRICULAPROFESSOR' in df.columns else ""
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
    st.sidebar.success(f"👤 {st.session_state.prof_email}")
    if st.sidebar.button("🔓 Logout"):
        st.session_state.clear()
        st.rerun()

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

    # Seleção de unidade, turma e disciplina
    unis = df_unid[df_unid['CHAPA/MATRICULA PROFESSOR'] == mat]['FILIAL'].unique()
    unidade = st.selectbox("Selecione sua unidade", options=unis)

    df_t = df_unid[(df_unid['CHAPA/MATRICULA PROFESSOR'] == mat) & (df_unid['FILIAL'] == unidade)]
    turmas = df_t['CODTURMA'].unique()
    turma = st.selectbox("Selecione sua turma", options=turmas)

    df_d = df_t[df_t['CODTURMA'] == turma]
    disciplinas = df_d['DISCIPLINA'].unique()
    disciplina = st.selectbox("Selecione a disciplina", options=disciplinas)

    # Determina SERIENORM da turma e DISCNORM da disciplina
    serie_norm = df_d['SERIENORM'].iloc[0] if not df_d.empty else None
    disc_norm = df_d[df_d['DISCIPLINA'] == disciplina]['DISCNORM'].iloc[0] if not df_d.empty else None

    # Filtra frentes (disciplinas do planejamento que correspondem a essa disciplina base)
    df_filtered = pd.DataFrame()
    if serie_norm and disc_norm:
        df_filtered = df_plan[(df_plan['SERIENORM'] == serie_norm) & (df_plan['DISCNORM'].str.contains(disc_norm, case=False))]

    # Seleção da frente
    frentes = df_filtered['DISCIPLINA'].unique()
    frente = st.selectbox("Selecione a frente da disciplina", options=frentes if len(frentes)>0 else ["Nenhuma frente disponível"])

    df_frente = df_filtered[df_filtered['DISCIPLINA'] == frente] if frente and frente != "Nenhuma frente disponível" else pd.DataFrame()

    st.write("### Planejamento Semanal")
    if not df_frente.empty:
        colunas_planejamento = [c for c in df_frente.columns if c.upper() in ['SEMANA','TÓPICO','SUBTÓPICO']]
        planej = df_frente[colunas_planejamento].copy()

        # Oculta linhas onde TÓPICO está vazio
        if 'TÓPICO' in planej.columns:
            planej = planej[planej['TÓPICO'].astype(str).str.strip() != '']

        # Carrega aulas já dadas para marcar automaticamente
        df_aulas = pd.DataFrame(safe_get_all_values(sheets['aulas']))
        df_aulas.columns = df_aulas.iloc[0]
        df_aulas = df_aulas[1:].reset_index(drop=True)

        planej['Marcar'] = False
        planej['Bloqueado'] = False
        for idx, row in planej.iterrows():
            ja_dada = not df_aulas[(df_aulas['Codigo Professor'] == mat) &
                                   (df_aulas['Unidade'] == unidade) &
                                   (df_aulas['Turma'] == turma) &
                                   (df_aulas['Disciplina'] == disciplina) &
                                   (df_aulas['Topico'] == row[colunas_planejamento[1]])].empty
            if ja_dada:
                planej.at[idx, 'Marcar'] = True
                planej.at[idx, 'Bloqueado'] = True

        planej_edit = st.data_editor(
            planej,
            column_config={"Marcar": st.column_config.CheckboxColumn("Aula dada")},
            disabled=planej['Bloqueado'].tolist(),
            hide_index=True
        )

        # Salvar aulas dadas
        if st.button("Salvar aulas dadas"):
            novas = []
            for idx, row in planej_edit.iterrows():
                if row['Marcar'] and not row['Bloqueado']:
                    novas.append([
                        st.session_state.prof_matricula,
                        unidade,
                        turma,
                        row[colunas_planejamento[0]],
                        disciplina,
                        row[colunas_planejamento[1]] if len(colunas_planejamento)>1 else '',
                        row[colunas_planejamento[2]] if len(colunas_planejamento)>2 else '',
                        '', ''
                    ])
            if novas:
                for r in novas:
                    safe_append_row(sheets['aulas'], r)
                st.success(f"{len(novas)} aulas registradas com sucesso!")
            else:
                st.info("Nenhuma aula nova para registrar.")
    else:
        st.info("Nenhum planejamento encontrado para esta disciplina/turma.")
else:
    st.stop()