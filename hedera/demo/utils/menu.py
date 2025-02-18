from dataclasses import dataclass
import inspect
from typing import Awaitable, Callable, Sequence

from ..utils.print import clear_screen, notify
from ..utils.prompt import prompt_loop


PROMPT = ">"


@dataclass
class PressResult:
    msg: str
    is_success: bool


@dataclass
class Ok(PressResult):
    msg: str = ""
    is_success: bool = True


@dataclass
class Fail(PressResult):
    msg: str = ""
    is_success: bool = False


@dataclass
class MenuEntry:
    key: str
    description: str
    on_press: Callable[[], Awaitable[PressResult]]


class Menu:
    def __init__(self, title, entries: Sequence[MenuEntry]):
        self.title = title

        self.entries_map = {}
        self.as_str = f"=== {self.title} ===\n"

        for entry in entries:
            if entry.key == "x":
                raise Exception("reserved key")

            self.entries_map[entry.key] = entry
            self.as_str += f"    ({entry.key})    {entry.description}\n"

        self.as_str += "    (x)    Close demo application\n"
        self.as_str += f" {PROMPT}"

    async def press_key(self, key):
        selected_entry = self.entries_map.get(key)

        clear_screen()

        if not selected_entry:
            return

        callback_method = selected_entry.on_press

        if inspect.iscoroutinefunction(callback_method):
            output = await callback_method()
        else:
            output = callback_method()

        if output.is_success and output.msg:
            notify(prefix="OUTPUT", msg=output.msg)
        elif not output.is_success:
            notify(prefix="FAIL", color="fg:ansired", msg=output.msg)

    async def user_interact(self):
        async for option in prompt_loop(self.as_str):
            if option == "x":
                break

            await self.press_key(option)
