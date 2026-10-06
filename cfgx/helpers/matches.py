def find_string(matches, identifier):
    for match in matches:
        if match.get("identifier") != identifier:
            continue

        data = match.get("data")

        if data is None:
            continue

        if not isinstance(data, bytes):
            continue

        try:
            value = data.decode("ascii")
        except UnicodeDecodeError:
            continue

        if value:
            return value

    return None


def find_references(matches, identifier):
    references = []

    for match in matches:
        if match.get("identifier") != identifier:
            continue

        match_references = match.get("references")

        if not match_references:
            continue

        for reference in match_references:

            if not isinstance(reference, dict):
                continue

            offset = reference.get("offset")

            if not isinstance(offset, int):
                continue

            if offset < 0:
                continue

            if reference not in references:
                references.append(reference)

    return references


def find_reference_data(matches, identifier):
    for match in matches:
        if match.get("identifier") != identifier:
            continue

        references = match.get("references")

        if not references:
            continue

        for reference in references:
            if not isinstance(reference, dict):
                continue

            data = reference.get("data")

            if not isinstance(data, bytes):
                continue

            if data:
                return data

    return None
