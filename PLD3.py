# Adição de caches para otimizar o acesso ao Google Sheets

import streamlit as st
import gspread
import bcrypt
import pandas as pd
from datetime import datetime
import time
from google.oauth2.service_account import Credentials
from functools import lru_cache

# ------------------------------------------------------------
# Configurações e credenciais
# ------------------------------------------------------------
CREDENCIAIS_JSON = "cred.json"
SHEET_ID = '13DvmOkiPjtXIaKLwNjBRU-klOoNzR3jmw0rNUioai7Y' # Substitua pelo seu ID de planilha

# =============================================================================
# SEÇÃO DE UTILITÁRIOS DE ACESSO AO GOOGLE SHEETS (Otimizada)
# =============================================================================

# NÍVEL 1: CACHE DE RECURSO - Conexão e Workbook
@st.cache_resource
def get_gspread_client():
    """Conecta ao Google Sheets usando as credenciais e faz cache da conexão."""
    try:
        scope = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds = Credentials.from_service_account_file(CREDENCIAIS_JSON, scopes=scope)
        return gspread.authorize(creds)
    except Exception as e:
        st.error(f"❌ Erro de autenticação com o Google Sheets: {e}")
        return None

@st.cache_resource
def get_workbook():
    """Abre a planilha principal (workbook) e faz cache do objeto."""
    client = get_gspread_client()
    if not client:
        return None
    try:
        return client.open_by_key(SHEET_ID)
    except Exception as e:
        st.error(f"❌ Não foi possível abrir a planilha. Verifique o SHEET_ID e as permissões: {e}")
        return None

# NÍVEL 2: CACHE DE MEMÓRIA RÁPIDA - Abas e Cabeçalhos
@lru_cache(maxsize=10)
def get_ws(title: str):
    """Obtém uma aba (worksheet) pelo título e faz cache com lru_cache."""
    wb = get_workbook()
    if wb:
        try:
            return wb.worksheet(title)
        except gspread.WorksheetNotFound:
            st.error(f"Aba da planilha com o nome '{title}' não foi encontrada.")
            return None
    return None

# NÍVEL 3: CACHE DE DADOS - Conteúdo das Planilhas
@st.cache_data(ttl=600) # Cache de 10 minutos
def load_full_sheet_as_df(ws_title: str):
    """Carrega uma aba inteira como DataFrame, ideal para abas de configuração."""
    ws = get_ws(ws_title)
    if not ws:
        return pd.DataFrame()
    
    values = ws.get_all_values()
    if not values or len(values) < 2:
        return pd.DataFrame(columns=values[0] if values else [])
    
    return pd.DataFrame(values[1:], columns=values[0])

# FUNÇÃO DE ESCRITA (NÃO DEVE SER CACHEADA)
def append_row_and_clear_cache(ws_title: str, row_data: list):
    """Adiciona uma nova linha e limpa os caches de dados para forçar a releitura."""
    ws = get_ws(ws_title)
    if ws:
        try:
            ws.append_row(row_data, value_input_option="USER_ENTERED")
            # Limpa TODOS os caches @st.cache_data para garantir que todos os usuários vejam os dados novos
            st.cache_data.clear()
            return True
        except Exception as e:
            st.error(f"Falha ao salvar na planilha '{ws_title}': {e}")
            return False
    return False

# =============================================================================
# Funções da Aplicação (usando a nova arquitetura)
# =============================================================================

def carregar_usuarios():
    df_usuarios = load_full_sheet_as_df('Info Professores')
    if df_usuarios.empty:
        return {}, pd.DataFrame()
        
    usuarios = {
        row['EMAILPROFESSOR'].strip().lower(): {
            "senha": row.get('SENHA', ""),
            "matricula": row.get('MATRICULAPROFESSOR', ""),
            "id_prof": row.get('ID + PROF', "")
        }
        for _, row in df_usuarios.iterrows() if 'EMAILPROFESSOR' in row and row['EMAILPROFESSOR']
    }
    return usuarios, df_usuarios

def salvar_usuario(email, senha_hash):
    ws = get_ws('Info Professores')
    df_usuarios_info = load_full_sheet_as_df('Info Professores') # Usa a função cacheada
    
    if ws and not df_usuarios_info.empty:
        col_senha_idx = df_usuarios_info.columns.get_loc('SENHA') + 1 if 'SENHA' in df_usuarios_info.columns else None
        if not col_senha_idx:
            st.error("Coluna 'SENHA' não encontrada na planilha 'Info Professores'.")
            return

        for idx, row_email in enumerate(df_usuarios_info['EMAILPROFESSOR']):
            if row_email.strip().lower() == email:
                ws.update_cell(idx + 2, col_senha_idx, senha_hash)
                st.cache_data.clear() # Invalida o cache após a alteração
                return

def registrar_log_acesso(email):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_row_and_clear_cache("logs", [email, "LOGIN_OK", timestamp])

# ------------------------------------------------------------
# Aplicação Streamlit
# ------------------------------------------------------------
st.set_page_config(page_title="Planejamento de Aulas", layout="wide", page_icon="🔐")

# Inicializa a conexão (fica em cache) e garante que o workbook está acessível
if get_workbook() is None:
    st.error("Falha crítica ao conectar com o Google Sheets. A aplicação não pode continuar.")
    st.stop()

if "etapa" not in st.session_state:
    st.session_state.etapa = "email"

# Carrega usuários usando a nova função cacheada
usuarios, df_info = carregar_usuarios()

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
                salvar_usuario(st.session_state.email, senha_hash)
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
                    registrar_log_acesso(email)
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

    # ---- CARREGAMENTO OTIMIZADO DE DADOS ----
    df_unid = load_full_sheet_as_df('Unidade+Discip')
    df_plan = load_full_sheet_as_df('Assunto+Marcacao')
    df_aulas = load_full_sheet_as_df('Aulas Dadas')
    # ---- FIM DO CARREGAMENTO OTIMIZADO ----
    
    if df_unid.empty or df_plan.empty:
        st.error("Não foi possível carregar os dados de planejamento. Verifique os nomes das abas e as permissões.")
        st.stop()

    # Normaliza colunas
    if 'SERIENORM' not in df_unid.columns: df_unid['SERIENORM'] = df_unid.iloc[:,5]
    if 'DISCNORM' not in df_unid.columns: df_unid['DISCNORM'] = df_unid.iloc[:,9]
    if 'SERIENORM' not in df_plan.columns: df_plan['SERIENORM'] = df_plan.iloc[:,3]
    if 'DISCNORM' not in df_plan.columns: df_plan['DISCNORM'] = df_plan.iloc[:,1]

    mat = st.session_state.prof_matricula
    id_prof = st.session_state.id_prof

    # Seleção de unidade, turma e disciplina (lógica inalterada)
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

    frentes = df_filtered['DISCIPLINA'].unique() if not df_filtered.empty and 'DISCIPLINA' in df_filtered.columns else []
    frente = st.selectbox("Selecione a frente da disciplina", options=frentes if len(frentes) > 0 else ["Nenhuma frente disponível"])

    df_frente = df_filtered[df_filtered['DISCIPLINA'] == frente].copy() if frente and frente != "Nenhuma frente disponível" else pd.DataFrame()

    st.write("### Planejamento Semanal")
    if not df_frente.empty:
        colunas_planejamento = [c for c in df_frente.columns if c.upper() in ['SEMANA', 'TÓPICO', 'SUBTÓPICO']]
        planej = df_frente[colunas_planejamento].copy()
        
        if 'TÓPICO' in planej.columns:
            planej = planej[planej['TÓPICO'].astype(str).str.strip() != ''].copy()

        planej['Aula Dada'] = False
        planej['Registrada'] = False

        if not df_aulas.empty:
            cols_to_str = ['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico']
            for col in cols_to_str:
                if col in df_aulas.columns:
                    df_aulas[col] = df_aulas[col].astype(str).str.strip()

            aulas_no_contexto = df_aulas[
                (df_aulas['Codigo Professor'] == str(id_prof).strip()) &
                (df_aulas['Unidade'] == str(unidade).strip()) &
                (df_aulas['Turma'] == str(turma).strip()) &
                (df_aulas['Disciplina'] == str(frente).strip())
            ]

            if not aulas_no_contexto.empty:
                topicos_registrados = set(aulas_no_contexto['Topico'])
                if 'TÓPICO' in planej.columns:
                    planej['Registrada'] = planej['TÓPICO'].apply(lambda topico: str(topico).strip() in topicos_registrados)
                    planej['Aula Dada'] = planej['Registrada']
        
        column_config = {
            "Aula Dada": st.column_config.CheckboxColumn("Aula Dada", help="Marque se a aula foi ministrada", disabled=False),
            "Registrada": st.column_config.CheckboxColumn("Registrada", help="Aula já registrada no sistema", disabled=True)
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
                if row['Aula Dada'] and not planej.at[idx, 'Registrada']:
                    topico = str(row['TÓPICO']) if 'TÓPICO' in row else ''
                    subtopico = str(row.get('SUBTÓPICO', '')) # Usar .get() para segurança

                    novas_aulas.append([
                        id_prof, unidade, turma,
                        datetime.now().strftime("%d/%m/%Y"),
                        frente, topico, subtopico, '', ''
                    ])
            
            if novas_aulas:
                aulas_salvas_count = 0
                for aula in novas_aulas:
                    if append_row_and_clear_cache('Aulas Dadas', aula):
                        aulas_salvas_count += 1
                
                if aulas_salvas_count > 0:
                    st.success(f"{aulas_salvas_count} aulas registradas com sucesso!")
                    time.sleep(1)
                    st.rerun()
            else:
                st.info("Nenhuma aula nova para registrar.")
    else:
        st.info("Nenhum planejamento encontrado para esta disciplina/turma.")

else:
    st.stop()