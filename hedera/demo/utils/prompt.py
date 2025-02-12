from prompt_toolkit import prompt as prompt_toolkit_prompt
from prompt_toolkit.eventloop import use_asyncio_event_loop
from prompt_toolkit.patch_stdout import patch_stdout


def prompt_init():
    if hasattr(prompt_init, "_called"):
        return

    prompt_init._called = True

    use_asyncio_event_loop()


async def prompt(*args, **kwargs):
    prompt_init()
    with patch_stdout():
        try:
            while True:
                tmp = await prompt_toolkit_prompt(*args, async_=True, **kwargs)
                if tmp:
                    break
            return tmp
        except EOFError:
            return None


async def prompt_loop(text):
    while True:
        option = await prompt(text)

        yield option
