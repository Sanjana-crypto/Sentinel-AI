import os
import json
from typing import AsyncGenerator, Optional, Any
from groq import AsyncGroq
from google.adk.models import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.models.llm_request import LlmRequest
from google.genai import types

class GroqLLM(BaseLlm):
    model: str = "llama-3.3-70b-versatile"

    @classmethod
    def supported_models(cls) -> list[str]:
        return ["llama.*", "gemma.*", "mixtral.*"]

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        
        client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))
        
        messages = []
        
        # 1. System Instruction
        if llm_request.config and llm_request.config.system_instruction:
            sys_text = llm_request.config.system_instruction
            if isinstance(sys_text, types.Content):
                sys_text = "".join(p.text for p in sys_text.parts if p.text)
            messages.append({"role": "system", "content": str(sys_text)})

        # 2. History & Contents
        for content in llm_request.contents:
            role = "user" if content.role == "user" else "assistant"
            
            text_parts = []
            tool_calls = []
            tool_results = []
            
            for part in content.parts:
                if part.text:
                    text_parts.append(part.text)
                elif part.function_call:
                    # Groq requires an ID. We construct a deterministic ID based on the function name.
                    call_id = f"call_{part.function_call.name}"
                    tool_calls.append({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": part.function_call.name,
                            "arguments": json.dumps(part.function_call.args)
                        }
                    })
                elif part.function_response:
                    call_id = f"call_{part.function_response.name}"
                    tool_results.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": part.function_response.name,
                        "content": json.dumps(part.function_response.response)
                    })

            if tool_results:
                messages.extend(tool_results)
            else:
                msg = {"role": role, "content": "".join(text_parts)}
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                messages.append(msg)

        # 3. Tools translation
        groq_tools = []
        if llm_request.config and llm_request.config.tools:
            for tool in llm_request.config.tools:
                if isinstance(tool, types.Tool) and tool.function_declarations:
                    for fd in tool.function_declarations:
                        # Groq doesn't like empty parameters dict, sometimes prefers omitted or empty object
                        params = fd.parameters.model_dump(exclude_none=True) if fd.parameters else {"type": "object", "properties": {}}
                        groq_tools.append({
                            "type": "function",
                            "function": {
                                "name": fd.name,
                                "description": fd.description or "",
                                "parameters": params
                            }
                        })

        # Ensure no tool_calls are passed without tools defined (edge cases)
        kwargs = {
            "model": self.model,
            "messages": messages,
        }
        if groq_tools:
            kwargs["tools"] = groq_tools
            kwargs["tool_choice"] = "auto"
            
        if llm_request.config:
            if llm_request.config.temperature is not None:
                kwargs["temperature"] = llm_request.config.temperature
            
            if llm_request.config.response_mime_type == "application/json":
                # Groq supports json_object natively
                kwargs["response_format"] = {"type": "json_object"}
                # Groq requires the prompt to explicitly mention JSON when using json_object
                messages.append({"role": "system", "content": "You MUST return the output in valid JSON format."})

        response = await client.chat.completions.create(**kwargs)
        
        # 4. Translate response to LlmResponse
        choice = response.choices[0]
        msg = choice.message
        
        parts = []
        if msg.content:
            parts.append(types.Part.from_text(text=msg.content))
            
        if msg.tool_calls:
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                parts.append(types.Part.from_function_call(name=tc.function.name, args=args))
                
        content_out = types.Content(role="model", parts=parts)
        
        yield LlmResponse(content=content_out)

