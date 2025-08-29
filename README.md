# Proposta de Melhoria de Segurança Cibernética para uma Empresa de Serviços Financeiros

## 1. Pentest como Processo:
A aplicação de um pentest é definida por etapas consecutivas e iterativas e possui diversas metodologias e/ou segue frameworks como o definido pela MITRE ATT&CK.:
	1. Preparação
		A etapa de preparação consiste na definição e elaboração dos documentos necessários para realizar o teste, onde se tem: acordo de confidencialidade, definição do escopo de teste, especificações da infraestrutura do alvo, objetivos do teste, estimativa de duração, regras na execução e informações adicionais caso necessárias. 
	2. Coleta de Informações
		A coleta de informações é comum ser dividida em 2 tipos:
			- Reconhecimento **passivo**, no qual busca-se informações sobre o alvo sem interação direta, por exemplo OSINT e Google Dorking. 
			- Reconhecimento **Ativo**, onde já ocorre interação com o alvo e é feita enumeração do alvo, por exemplo Enumeração de: Infraestrutura, Serviços e Hosts, com destaque ao uso da ferramenta NMAP durante essa etapa.
	3. Análise de Vulnerabilidades
		Esta etapa se baseia nos achados durante a coleta de informações e informações da infraestrutura fornecidas pelo cliente. Durante a etapa, pode ser feita uma análise manual ou automatizada através do uso de ferramentas.
	4. Exploração
		 Com os resultados obtidos na etapa de análise de vulnerabilidades, os possíveis vetores de intrusão são identificados a fim de explorar brechas na segurança da infraestrutura para obter acesso inicial a esses sistemas. A finalidade da etapa de exploração, é obter o acesso inicial ao sistema alvo.
	5. Pós-Exploração
		Assim que se obtém acesso inicial à máquina alvo, deve-se garantir que o acesso a ela seja mantido, além disso, é essencial buscar o aumento nos privilégios de acesso para obter as permissões mais irrestritas e elevadas possíveis.
	6. Movimentação Lateral
		A etapa de movimentação lateral apresenta um processo de execução similar à etapa de pós-exploração, sendo a principal diferença entre elas o resultado, pois na etapa anterior busca-se elevar os privilégios e acessos ao sistema, já na movimentação lateral o objetivo é obter um maior reconhecimento do ambiente e ainda, buscar alternativas para conseguir acessos de administrador por meio de outras possíveis vulnerabilidades que podem ser encontradas ao explorar o sistema.
	7. Prova de Conceito
		Nesta etapa tem-se como objetivo elaborar um documento objetivo com os passos que foram executados para comprometer o sistema alvo. No documento deve constar as ferramentas que foram utilizadas, comandos, possíveis referências, para demonstrar ao cliente de forma sucinta e dinâmica como comprometer o sistema, de forma que o cliente possa averiguar até mesmo pessoalmente que o sistema está vulnerável
	8. Conclusão
		Por fim tem-se a etapa de conclusão, onde os resultados são entregues por meio de um relatório administrativo, com explicações abstraídas para o corpo executivo/administrativo do cliente, e um relatório completo, contendo explicações técnicas e fundamentações sobre as descobertas durante o processo. Além disso, a entrega também consiste na prova de conceito elaborada previamente.

## 2. Implementação do SOC:
### Plano de ação para implementação:
#### Fase 1: Planejamento e Estruturação
1. **Avaliação e Escopo:**
    - **Definição de objetivos:** Estabelecer o que a empresa espera alcançar com o SOC, como a redução do tempo de resposta a incidentes ou a conformidade com regulamentações.
    - **Análise de risco:** Identificar os ativos mais críticos e as ameaças mais prováveis para direcionar os esforços de segurança.
    - **Levantamento de requisitos:** Mapear os sistemas, aplicações e dados que precisarão ser monitorados.
    
2. **Estrutura Organizacional e Equipe:**
    - **Definição de papéis:** Criar uma estrutura de equipe clara com responsabilidades bem definidas. As principais funções incluem:
        - **Analista de SOC (Nível 1):** Responsável pelo monitoramento inicial, triagem de alertas e escalonamento de incidentes.
        - **Analista de SOC (Nível 2):** Realiza investigações mais aprofundadas, analisa malwares e utiliza ferramentas forenses.
        - **Engenheiro de Segurança:** Gerencia e otimiza as ferramentas de segurança, como o SIEM e firewalls.
        - **Líder de Equipe de SOC:** Supervisiona a equipe, desenvolve estratégias e se comunica com a alta gestão.
    - **Treinamento:** Oferecer treinamento contínuo para a equipe em novas ameaças, ferramentas e procedimentos de resposta a incidentes.

#### Fase 2: Implementação Técnica
1. **Seleção e Implantação de Ferramentas:**
    - **Ferramenta SIEM (Security Information and Event Management):** O SIEM é a espinha dorsal do SOC. Ele centraliza e correlaciona dados de segurança de diversas fontes.
        - **Opções de Ferramentas SIEM:**
            - **Open-Source:** **Wazuh, ELK Stack (Elasticsearch, Logstash, Kibana)**. São ferramentas flexíveis, mas exigem mais conhecimento técnico para configuração e manutenção.
            - **Comerciais:** **Splunk, Microsoft Sentinel, IBM QRadar, Palo Alto Cortex XSOAR**. Oferecem recursos mais robustos, suporte técnico e interfaces mais amigáveis, mas com um custo de licença significativo.
    - **Outras Ferramentas Essenciais:**
        - **Sistemas de Detecção de Intrusão (IDS/IPS):** Snort ou Suricata para monitorar o tráfego de rede.
        - **Ferramentas de Análise Forense:** The Sleuth Kit (TSK) ou Volatility Framework para investigar incidentes.
        - **Ferramentas de Ticketing e Gerenciamento de Incidentes:** JIRA ou ServiceNow para documentar e rastrear incidentes.

2. **Configuração e Integração:**
    - **Coleta de logs:** Conectar o SIEM a todas as fontes de dados relevantes, como firewalls, servidores, endpoints, sistemas de autenticação e aplicações. A coleta precisa e padronizada é fundamental.
    - **Criação de regras de correlação:** Desenvolver regras no SIEM para identificar padrões de comportamento suspeito. Por exemplo, múltiplas tentativas de login falhas seguidas por um login bem-sucedido em um sistema crítico.
    - **Criação de dashboards e relatórios:** Personalizar painéis de visualização no SIEM para monitoramento em tempo real e relatórios para a gestão.

#### Fase 3: Operação e Melhoria Contínua
1. **Processos de Resposta a Incidentes (IRP):**
    - Desenvolver e documentar um plano de resposta a incidentes (IRP) detalhado, que servirá como um guia para a equipe durante um evento de segurança. O processo típico inclui as seguintes etapas:
        1. **Preparação:** Mapear ativos, definir responsabilidades e manter o IRP atualizado.
        2. **Detecção e Análise:** O SIEM gera um alerta, e a equipe do SOC analisa a criticidade e a veracidade da ameaça.
        3. **Contenção:** Isolar os sistemas afetados para impedir que o ataque se espalhe.
        4. **Erradicação:** Remover o malware ou a causa-raiz do incidente.
        5. **Recuperação:** Restaurar os sistemas para um estado seguro.
        6. **Pós-Incidente (Lições Aprendidas):** Analisar o incidente, documentar as lições aprendidas e atualizar os processos de segurança para evitar futuras ocorrências.

2. **Monitoramento e Otimização:**
    - **Monitoramento 24/7:** Manter a vigilância constante dos sistemas.
    - **Gestão de ameaças e vulnerabilidades:** Manter a equipe atualizada sobre novas ameaças e aplicar patches de segurança.
    - **Exercícios de simulação:** Realizar simulações de incidentes (exercícios de "Red Team" e "Blue Team") para testar a eficácia dos processos e a prontidão da equipe.

### Proposta de Ferramentas SIEM e Resposta a Incidentes:
#### 1. Ferramenta SIEM
A escolha da ferramenta SIEM dependerá do orçamento e da maturidade técnica da empresa **FinTechSecure**.

   - **Wazuh (início/custo baixo):** Open source, sem licença, bom para pequenos e médios ambientes. Requer mais configuração.
   - **Splunk (avançado):** Comercial, muito robusto e escalável. Alto custo de licença.
   - **Microsoft Sentinel (cloud):** Nativo da Azure, fácil de implementar e manter. Custos variáveis conforme uso.   

#### 2. Processos de Resposta a Incidentes
O NIST Cyber security Framework (CSF), é um framework de grande respaldo no mercado, por isso será utilizado como base. Ele reforça que o processo de resposta a incidentes é **iterativo**: cada incidente deve retroalimentar a fase de **Identify** e **Protect**, fortalecendo a maturidade da organização. Vale ressaltar que dentro dos requisitos do projeto, tem-se destaque a partir da etapa 3, sendo as etapas 1 e 2 com foco maior em governança e **gestão de vulnerabilidade** (próximo tópico).
##### 1. Identify (Identificar)
Objetivo: conhecer os ativos, riscos e contexto para que a resposta seja direcionada.
- Manter inventário de ativos e sistemas críticos.
- Classificar dados e processos por importância e sensibilidade.
- Avaliar riscos de segurança e dependências.
- Definir papéis e responsabilidades no plano de resposta a incidentes.
##### 2. Protect (Proteger)
Objetivo: reduzir a probabilidade e o impacto de incidentes.
- Implementar controles de acesso e autenticação robusta.
- Aplicar hardening em sistemas e segmentação de rede.
- Configurar políticas de logging e centralização de registros.
- Treinar usuários e equipes para prevenção (awareness, phishing, boas práticas).
- Criar planos de resposta documentados e testados (tabletop exercises).
##### 3. Detect (Detectar)
Objetivo: identificar rapidamente anomalias que possam indicar incidentes.
- Monitorar logs de rede, sistemas e aplicações.
- Definir alertas para eventos suspeitos (ex.: tentativas de login falhas, tráfego incomum).
- Correlacionar eventos para distinguir incidentes de falsos positivos.
- Estabelecer métricas de tempo de detecção (MTTD).
##### 4. Respond (Responder)
Objetivo: mitigar o impacto, conter a ameaça e entender a causa raiz.
**Etapas principais:**
- **Análise inicial**: confirmar o incidente e classificar criticidade.
- **Coleta de evidências**: logs, imagens de disco/memória, registros de rede, com preservação da integridade.
- **Contenção**:
    - Curto prazo → isolar sistemas afetados, bloquear contas comprometidas, segmentar rede.
    - Longo prazo → aplicar patches, revisar configurações, endurecer acessos.
- **Erradicação**: remover malware, revogar credenciais, corrigir vulnerabilidades.
- **Comunicação**: notificar stakeholders internos e externos conforme necessidade (usuários, parceiros, autoridades).
- **Documentação**: registrar cada ação tomada e os achados.
##### 5. Recover (Recuperar)
Objetivo: restaurar operações e aumentar resiliência futura.
- Reinstalar ou restaurar sistemas afetados a partir de backups íntegros.
- Monitorar ambiente após a recuperação para detectar reinfecções.
- Validar a eficácia dos controles aplicados.
- Revisar políticas e procedimentos com base no aprendizado.
- Realizar sessão de _lessons learned_ para atualizar planos de resposta e melhorar capacidades.

## 3. Gestão de Vulnerabilidades:
Como citado no tópico anterior, os fundamentos da gestão de Vulnerabilidades podem ter início nas etapas 1 e 2 do NIST CSF. Para complemento de uma política de gestão mais robusta, também será utilizada como base a norma ISO 27001 e o CIS Controls.
	- ISO 27001: controles A.12.6.1 (Gestão de vulnerabilidades técnicas) e A.14 (Segurança em sistemas de desenvolvimento).
	- CIS Controls:
		- CSC 07 → Continuous Vulnerability Management
		- CSC 03 → Continuous Data Protection
		- CSC 04 → Secure Configuration
### Objetivos
- Garantir que vulnerabilidades em ativos críticos da FinTechSecure sejam identificadas, avaliadas, priorizadas e corrigidas de forma sistemática.
- Reduzir riscos de exploração e proteger dados sensíveis e segredos corporativos.
- Criar um ciclo contínuo de melhoria em segurança, integrado ao SOC em implantação.
### Escopo
- Inclui todos os sistemas, redes, aplicações, APIs, infraestrutura em nuvem e endpoints da FinTechSecure.
- Engloba tanto ativos internos quanto externos (expostos à internet).
### Responsabilidades
- **SOC**: monitoramento, coleta de alertas e análise de logs.
- **Time de Segurança**: execução de varreduras periódicas, análise de vulnerabilidades e priorização.
- **Times de TI/DevOps**: aplicar correções, patches e mitigações.
- **Gestão Executiva**: garantir recursos e governança.
### Ciclo de Gestão de Vulnerabilidades
1. **Descoberta e Inventário** (NIST: Identify / CIS CSC 01 & 02)
    - Manter inventário atualizado de ativos digitais e fluxos de dados.
    - Automatizar descoberta de novos ativos e serviços expostos.        
2. **Varredura Periódica** (NIST: Detect / ISO 27001 A.12.6.1 / CIS CSC 07)
    - Realizar _scans_ de vulnerabilidades semanalmente em ambientes críticos e mensalmente nos demais.
    - Usar _pentests_ trimestrais em sistemas de alto risco.
3. **Avaliação de Risco** (NIST: Identify / CIS CSC 07)
    - Classificação das vulnerabilidades usando **CVSS (Common Vulnerability Scoring System)**
    - Considerar não só a pontuação CVSS, mas também:
        - Exposição do ativo (internet x interno).
        - Existência de exploits conhecidos.
        - Valor do ativo para o negócio (sistemas bancários, pagamentos, segredos corporativos).
4. **Priorização e Correção** (NIST: Respond / ISO 27001 A.12.6.1)
    - **Crítico (CVSS ≥ 9.0)** → corrigir em até 72h.
    - **Alto (7.0 – 8.9)** → corrigir em até 7 dias.
    - **Médio (4.0 – 6.9)** → corrigir em até 30 dias.
    - **Baixo (< 4.0)** → corrigir em até 90 dias ou aceitar risco mediante aprovação.
5. **Mitigação e Compensação**
    - Aplicar controles compensatórios: firewall, segmentação, monitoramento reforçado.
6. **Validação e Teste** (NIST: Recover / CIS CSC 07)
    - Reexecutar varreduras após correções.
    - Validar ausência de impacto operacional.
7. **Documentação e Relatórios** (ISO 27001 A.16.1)
    - Registro de todas as vulnerabilidades encontradas, classificações, responsáveis e status.
    - Relatórios mensais ao comitê de segurança.
8. **Melhoria Contínua**
    - Revisão semestral da política com base em novos riscos, mudanças regulatórias e incidentes.
### Métricas de Risco e Indicadores
- **CVSS Score**: base para classificação inicial.
- **Tempo médio de correção (MTTR)** → SLA de correção por criticidade.
- **Taxa de Conformidade** → % de vulnerabilidades resolvidas dentro do prazo.
- **Número de ativos críticos descobertos fora do inventário**.
- **Percentual de vulnerabilidades reincidentes** (mesmo problema reaparecendo após patch).
### Integração com SOC
- Centralização de alertas de varredura e correlação com logs de incidentes.
- Monitoramento em tempo real de tentativas de exploração conhecidas (exploits públicos).
- Automação para bloquear acessos maliciosos em ativos vulneráveis até que a correção seja aplicada.

## 4. Gestão de Dados Sensíveis:
### Políticas de Proteção de Dados
- **Classificação da Informação** (ISO 27001 + 27701):
    - Identificação e categorização de dados pessoais, financeiros e críticos.
    - Diferenciar **dados pessoais comuns** de **dados pessoais sensíveis** (ex.: biometria, dados financeiros, localização).
- **Política de Privacidade e Tratamento de Dados**:
    - Documentar como os dados pessoais são coletados, usados, retidos e descartados.
    - Definir papéis claros: **Controlador, Operador e Encarregado (DPO)**.
- **Retenção e Descarte** (ISO 27701 §7.4.6):
    - Estabelecer ciclos de retenção baseados em requisitos legais (ex.: Banco Central, LGPD).
    - Garantir descarte seguro por limpeza criptográfica e registros de eliminação.
- **Consentimento e Transparência**:
    - Garantir que clientes sejam informados sobre coleta e uso dos dados.
    - Registrar e gerenciar consentimentos (opt-in e opt-out).
### Controles Técnicos de Proteção
- **Criptografia** (ISO 27001 A.10.1 / ISO 27701 §7.4.5):
    - Dados pessoais e sensíveis protegidos com **AES-256 em repouso** e **TLS 1.3 em trânsito**.
    - Políticas de rotação e segregação de chaves em KMS.
- **Gestão de Segredos**:
    - Implementação de **cofre de segredos** (HashiCorp Vault, AWS Secrets Manager).
    - Rotação automática de senhas, tokens e chaves de API.
- **Controles de Acesso** (ISO 27001 A.9 / ISO 27701 §7.4.3):
    - RBAC + ABAC para dados sensíveis.
    - **MFA obrigatório** para colaboradores, parceiros e sistemas críticos.
    - Monitoramento contínuo de acessos privilegiados (PAM – Privileged Access Management).
- **Anonimização e Pseudonimização** (ISO 27701 §7.4.8):
    - Minimizar exposição de dados sensíveis em ambientes de teste e relatórios.
    - Implementar técnicas de tokenização para dados financeiros.
### Monitoramento e Auditoria
- **Auditoria e Conformidade**:
    - Revisões periódicas de conformidade com ISO 27701 e LGPD/GDPR.
    - Registros de atividades de processamento de dados (Data Processing Records).
- **Detecção de Incidentes**:
    - SOC integrado com alertas específicos para acessos ou exfiltrações de dados sensíveis.
    - Processos de notificação de incidentes em até 72h (GDPR) ou conforme LGPD.
### Cultura e Treinamento
- **Treinamentos periódicos** sobre proteção de dados pessoais, privacidade e boas práticas.
- **Campanhas internas de conscientização** sobre manuseio seguro de informações.
- Simulações de incidentes de vazamento de dados para testar resposta e resiliência.

## 5. Gestão de Segredos:
A gestão de Segredos se alinha fortemente com a Gestão de Dados Sensíveis, visto a necessidade de gerir os dados de forma sólida.
### Política de Gestão de Segredos
- **Escopo**: Abrange senhas de sistemas, chaves de API, certificados digitais, tokens de autenticação, credenciais de banco de dados e chaves de criptografia.
- **Proibição de armazenamento inseguro**:
    - Nunca incluir senhas ou tokens em **código-fonte, logs ou planilhas locais**.
    - Bloqueio automático de commits suspeitos em repositórios (ex.: Git hooks, scanners como _git-secrets_).
- **Princípio do Mínimo Privilégio (Least Privilege)**:
    - Cada segredo deve ser acessível **somente por quem ou pelo que precisa dele**.
    - Implementação de RBAC/ABAC para limitar acesso a segredos.
- **Centralização e Rastreamento**:
    - Todos os segredos devem ser armazenados em um **cofre seguro** (Secrets Manager).
    - Auditoria obrigatória: todos os acessos a segredos devem ser registrados e revisados periodicamente.
### Ferramentas Recomendadas
- **HashiCorp Vault** → solução robusta e on-premise/cloud, com controle de acesso dinâmico e rotação automatizada.
- **AWS Secrets Manager** (se a infraestrutura estiver em AWS) → rotação nativa de segredos de bancos e APIs.
- **Azure Key Vault / Google Secret Manager** → equivalente para nuvens híbridas.
- **Kubernetes Secrets + Sealed Secrets** → para orquestração segura em ambientes de containers.
### Práticas de Rotação
- **Rotação Automática**:
    - Senhas de banco de dados e tokens de API devem ser trocados automaticamente em ciclos definidos (ex.: a cada 90 dias, ou imediatamente em caso de suspeita de vazamento).
    - Integração do cofre de segredos com serviços para atualizar credenciais sem downtime.
- **Expiração de Segredos**:
    - Definir TTL (Time To Live) para cada segredo — expiração automática e renovação sob demanda.
- **Segregação de Ambientes**:
    - Segredos diferentes para **desenvolvimento, teste e produção**.
    - Acesso cruzado proibido entre ambientes.
### Controles de Acesso
- **MFA + RBAC/ABAC**:
    - Todos os acessos administrativos ao cofre exigem **autenticação multifator**.
    - Perfis de acesso ajustados por função (Dev, DBA, Operações, SOC).
- **Just-In-Time Access (JIT)**:
    - Acesso temporário concedido apenas durante o tempo necessário.
- **Monitoramento e Alertas**:
    - Detecção de acessos fora do padrão (horário, geolocalização, número de tentativas).
    - Integração com SOC para resposta a incidentes.
### Governança e Conformidade
- **Política de Revisão Periódica**: revisão trimestral de todos os segredos ativos.
- **Auditorias Internas e Externas**: comprovar conformidade com **ISO 27001, ISO 27701 e PCI-DSS**.
- **Registro de Responsabilidade**: cada segredo deve ter um "dono" responsável por seu ciclo de vida.
