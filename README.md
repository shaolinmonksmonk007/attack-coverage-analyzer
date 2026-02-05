git clone https://github.com/shaolinmonksmonk007/attack-coverage-analyzer.git
cd attack-coverage-analyzer

# create env and install deps (optional but recommended)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# edit .env and put real OPENAI_API_KEY

python main.py
