import os
import asyncio
from dotenv import load_dotenv
from app.groq_llm import GroqLLM
from google.adk.models.llm_request import LlmRequest
from google.genai import types

load_dotenv(override=True)

async def test():
    model = GroqLLM(model="llama-3.3-70b-versatile")
    
    request = LlmRequest(
        model=model.model,
        contents=[
            types.Content(role="user", parts=[types.Part.from_text(text="What is the capital of France?")])
        ],
        config=types.GenerateContentConfig()
    )
    
    print("Sending request to GroqLLM...")
    async for response in model.generate_content_async(request):
        text = "".join(p.text for p in response.content.parts if p.text)
        print("Response chunk:", text)
        print("Raw Parts:", response.content.parts)

if __name__ == "__main__":
    asyncio.run(test())
