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
    # MODIFICAÇÃO: Exibir ID + PROF no painel lateral em vez do email
    

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
#-------------------------------------------------------------------------------------------------------------------------
 # Seleção de disciplina com a nova lógica de comparação
    df_d = df_t[df_t['CODTURMA'] == turma]
    
    # MODIFICAÇÃO: Nova lógica para filtrar disciplinas
    disciplinas_disponiveis = []
    for _, row in df_d.iterrows():
        disc_norm_unid = str(row['DISCNORM']).strip().lower()
        
        # Verifica se existe pelo menos um registro em df_plan onde DISCNORM contém disc_norm_unid
        if not df_plan[df_plan['DISCNORM'].str.lower().str.contains(disc_norm_unid, regex=False)].empty:
            disciplinas_disponiveis.append(row['DISCIPLINA'])
    
    disciplinas = list(set(disciplinas_disponiveis))  # Remove duplicatas
    disciplina = st.selectbox("Selecione a disciplina", options=disciplinas if disciplinas else ["Nenhuma disciplina disponível"])

    # Determina SERIENORM e DISCNORM com a nova lógica
    serie_norm = df_d[df_d['DISCIPLINA'] == disciplina]['SERIENORM'].iloc[0] if disciplina and disciplina != "Nenhuma disciplina disponível" else None
    disc_norm = df_d[df_d['DISCIPLINA'] == disciplina]['DISCNORM'].iloc[0] if disciplina and disciplina != "Nenhuma disciplina disponível" else None
#-------------------------------------------------------------------------------------------------
        # Filtra frentes com a nova lógica de comparação
    df_filtered = pd.DataFrame()
    if serie_norm and disc_norm:
        # MODIFICAÇÃO: Filtra onde DISCNORM de Assunto+Marcacao CONTÉM DISCNORM de Unidade+Discip
        df_filtered = df_plan[
            (df_plan['SERIENORM'] == serie_norm) & 
            (df_plan['DISCNORM'].str.lower().str.contains(disc_norm.lower(), regex=False))
        ].copy()  # Usar copy() para evitar SettingWithCopyWarning

    # MODIFICAÇÃO: Verificar se a coluna 'DISCIPLINA' existe no DataFrame filtrado
    if not df_filtered.empty and 'DISCIPLINA' in df_filtered.columns:
        frentes = df_filtered['DISCIPLINA'].unique()
    else:
        frentes = []
    
    frente = st.selectbox("Selecione a frente da disciplina", 
                         options=frentes if len(frentes) > 0 else ["Nenhuma frente disponível"])

    # MODIFICAÇÃO: Definir df_frente de forma segura
    if frente and frente != "Nenhuma frente disponível" and not df_filtered.empty and 'DISCIPLINA' in df_filtered.columns:
        df_frente = df_filtered[df_filtered['DISCIPLINA'] == frente].copy()
    else:
        df_frente = pd.DataFrame()

    #-------------------------------------------------------------------------------------------------

    st.write("### Planejamento Semanal")
    if not df_frente.empty:
        # Definir colunas_planejamento de forma segura
        colunas_planejamento = [c for c in df_frente.columns if c.upper() in ['SEMANA', 'TÓPICO', 'SUBTÓPICO']]
        
        # CORREÇÃO: Definir planej corretamente como uma cópia
        planej = df_frente[colunas_planejamento].copy() if not df_frente.empty else pd.DataFrame()
        
        # Verificar se planej foi criado corretamente
        if planej.empty:
            st.warning("Nenhum dado de planejamento encontrado para os filtros selecionados.")
            st.stop()

        # Remover linhas vazias de forma segura
        if 'TÓPICO' in planej.columns:
            planej = planej[planej['TÓPICO'].astype(str).str.strip() != ''].copy()
        
        # Carregar aulas já dadas
        try:
            df_aulas = pd.DataFrame(safe_get_all_values(sheets['aulas']))
            if not df_aulas.empty:
                df_aulas.columns = df_aulas.iloc[0]
                df_aulas = df_aulas[1:].reset_index(drop=True)
            else:
                df_aulas = pd.DataFrame(columns=['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico'])
        except Exception as e:
            st.error(f"Erro ao carregar aulas dadas: {e}")
            df_aulas = pd.DataFrame(columns=['Codigo Professor', 'Unidade', 'Turma', 'Disciplina', 'Topico'])

        # Inicializar colunas de controle
        planej['Aula Dada'] = False
        planej['Registrada'] = False
        
        # Verificar cada tópico no planejamento
        for idx, row in planej.iterrows():
            try:
                topico = str(row[colunas_planejamento[1]]) if len(colunas_planejamento) > 1 else ''
                subtopico = str(row[colunas_planejamento[2]]) if len(colunas_planejamento) > 2 else ''
                
                # Verificar se já existe registro
                registro_existe = not df_aulas[
                    (df_aulas['Codigo Professor'].astype(str).str.contains(str(mat))) &
                    (df_aulas['Unidade'].astype(str) == str(unidade)) &
                    (df_aulas['Turma'].astype(str) == str(turma)) &
                    (df_aulas['Disciplina'].astype(str) == str(disciplina)) &
                    (df_aulas['Topico'].astype(str) == topico) &
                    (df_aulas.get('Subtopico', '').astype(str) == subtopico)
                ].empty
                
                if registro_existe:
                    planej.at[idx, 'Aula Dada'] = True
                    planej.at[idx, 'Registrada'] = True
            except Exception as e:
                st.error(f"Erro ao verificar registro para linha {idx}: {e}")
                continue

        # Configurar editor de dados
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

        # Exibir editor
        planej_edit = st.data_editor(
            planej,
            column_config=column_config,
            disabled=["Registrada"],
            hide_index=True,
            key=f"editor_{unidade}_{turma}_{disciplina}"
        )

        # Processar salvamento
        if st.button("Salvar aulas dadas"):
            novas_aulas = []
            for idx, row in planej_edit.iterrows():
                try:
                    if row['Aula Dada'] and not planej.at[idx, 'Registrada']:
                        topico = str(row[colunas_planejamento[1]]) if len(colunas_planejamento) > 1 else ''
                        subtopico = str(row[colunas_planejamento[2]]) if len(colunas_planejamento) > 2 else ''
                        
                        # Verificar novamente antes de salvar
                        registro_existe = not df_aulas[
                            (df_aulas['Codigo Professor'].astype(str).str.contains(str(mat))) &
                            (df_aulas['Unidade'].astype(str) == str(unidade)) &
                            (df_aulas['Turma'].astype(str) == str(turma)) &
                            (df_aulas['Disciplina'].astype(str) == str(frente)) &  # MODIFICAÇÃO: Usar o valor da frente selecionada
                            (df_aulas['Topico'].astype(str) == topico) &
                            (df_aulas.get('Subtopico', '').astype(str) == subtopico)
                        ].empty
                        
                        if not registro_existe:
                            novas_aulas.append([
                                st.session_state.id_prof,  # MODIFICAÇÃO: Usar somente o ID + PROF
                                unidade,
                                turma,
                                datetime.now().strftime("%d/%m/%Y"),
                                frente,  # MODIFICAÇÃO: Usar o valor da frente selecionada
                                topico,
                                subtopico,
                                '', ''
                            ])
                except Exception as e:
                    st.error(f"Erro ao processar linha {idx}: {e}")
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