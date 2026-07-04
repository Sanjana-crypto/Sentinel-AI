import os
from dotenv import load_dotenv
import asyncio
from groq import AsyncGroq

load_dotenv(override=True)

async def test_groq():
    api_key = os.getenv("GROQ_API_KEY")
    print(f"Loaded GROQ_API_KEY: {'YES' if api_key else 'NO'}")
    if not api_key:
        print("Error: GROQ_API_KEY is not set.")
        return

    client = AsyncGroq(api_key=api_key)
    try:
        print("Sending request to Groq...")
        chat_completion = await client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": "Say Hello",
                }
            ],
            model="llama3-8b-8192",
        )
        print("Success:", chat_completion.choices[0].message.content)
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_groq())
