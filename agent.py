
import os
import google.generativeai as genai
import dotenv

dotenv.load_dotenv()

genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 500000,
    "response_mime_type": "application/json",
}
model = genai.GenerativeModel("gemini-1.5-flash", generation_config=generation_config)



model = genai.GenerativeModel("gemini-1.5-flash")

prompt = """Tell basically what is suricatta  and how it works.
Suricata is an open-source network threat detection engine that provides intrusion detection, intrusion prevention,"""        
response = model.generate_content( prompt)
print(response.text)