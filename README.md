
# Como dar criar ao ambiente virtual de python

Um ambiente virtual do python serve apenas para evitar instalar bibliotecas no python do computador.
Criando assim um ambiente python especifico para o projeto, comum a todos os devs.

Para criar, executar no terminal:
- python -m venv [ENV_NAME]

ENV_NAME pode ser qualquer um mas depois adiciona o nome que deres ao .gitignore para não dares commit do environment.
Ou então dás o mesmo nome que usei "ENV_TP1".

# Como dar init ao ambiente

Executar no terminal
- .\[ENV_NAME]\Scripts\activate

Ao ativares deves ver no terminal algo do genero:
- (ENV) C:\path\to\current\folder:

# Como instalar as bibliotecas usadas (presentes no ficheiro libs.txt)

Iniciar o ambiente virtual e executar no terminal
- pip install -r libs.txt

# Como guardar novas bibliotecas instalada para o projeto

Executar no terminal
- pip freeze >> libs.txt

# Como desativar o ambiente e voltar ao normal

Executar no terminal
- deactivate

