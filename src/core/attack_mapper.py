from typing import Dict, List, Any
import openai
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

class AttackMapper:
    """LLM-based mapper: rule → MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        if not config.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required.")
        openai.api_key = config.OPENAI_API_KEY
        self.model = config.OPENAI_MODEL

    async def map_rule(self, parsed_rule: Dict[str, Any]) -> Dict[str, Any]:
        """Map one rule to ATT&CK techniques using GPT-4."""
        system_prompt = (
            "You are a detection engineering assistant. "
            "Given a SIEM detection rule (name, platform, query, description, indicators, data sources), "
            "map it to the most relevant MITRE ATT&CK techniques.\n\n"
            "Return STRICT JSON with this exact structure:\n"
            "{\n"
            "  \"techniques\": [\n"
            "    {\"id\": \"T1059.001\", \"name\": \"PowerShell\", \"confidence\": 0.9},\n"
            "    {\"id\": \"T1059\", \"name\": \"Command and Scripting Interpreter\", \"confidence\": 0.8}\n"
            "  ]\n"
            "}\n"
        )

        user_prompt = f"""
Rule:
Name: {parsed_rule.get('name')}
Platform: {parsed_rule.get('platform')}
Description: {parsed_rule.get('description')}
Query: {parsed_rule.get('query')}

Indicators: {parsed_rule.get('indicators')}
Data sources: {parsed_rule.get('data_sources')}
"""

        try:
            resp = await openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            content = resp.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            return {"techniques": []}

        try:
            import json
            data = json.loads(content)
            techniques = data.get("techniques", [])
        except Exception as e:
            logger.error(f"Failed to parse LLM JSON: {e}")
            techniques = []

        return {
            "rule_name": parsed_rule.get("name"),
            "platform": parsed_rule.get("platform"),
            "techniques": techniques,
        }

    async def map_rules(self, parsed_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for r in parsed_rules:
            mapped = await self.map_rule(r)
            results.append(mapped)
        return results
