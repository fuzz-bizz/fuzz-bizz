# stringasxml.py
#
# This support library enables us to process LLM outputs as XML without having to use XML libraries.
# This is good because LLMs may hallucinate, meaning that its output is not always parseable. But if
# we ensure that there are no nested tags of the same name, we can still process these outputs
# effectively.

def extract(text: str, token: str):
    """Extract all occurrences of <token>...</token> from text.

    Assumes tags of the same name are not nested.
    Does not use any XML parsing library.
    """
    results = []
    start_tag = f"<{token}>"
    end_tag = f"</{token}>"

    start = 0
    while True:
        # find the next opening tag
        start_index = text.find(start_tag, start)
        if start_index == -1:
            break

        # find the closing tag after it
        end_index = text.find(end_tag, start_index + len(start_tag))
        if end_index == -1:
            break  # malformed, but we just stop

        # extract content
        content_start = start_index + len(start_tag)
        content = text[content_start:end_index]
        results.append(content)

        # move past this closing tag to look for more
        start = end_index + len(end_tag)

    return results
