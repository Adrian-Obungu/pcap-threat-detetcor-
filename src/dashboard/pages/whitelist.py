def show():
    import streamlit as st
    from whitelist.manager import load_whitelist, add_whitelist_entry, remove_whitelist_entry

    st.header("Whitelist Manager")
    st.write("Current whitelist entries:")

    entries = load_whitelist()
    for entry in entries:
        col1, col2 = st.columns([4, 1])
        col1.write(entry)
        if col2.button("Delete", key=entry):
            if remove_whitelist_entry(entry):
                st.success(f"Removed {entry}")
                st.rerun()
            else:
                st.error("Failed to remove.")

    st.subheader("Add new entry")
    new_entry = st.text_input("Entry (IP:MAC, IP, domain, or src:dest:proto)")
    if st.button("Add"):
        from whitelist.manager import add_whitelist_entry, validate_line
        valid, category = validate_line(new_entry)
        if valid:
            if add_whitelist_entry(new_entry):
                st.success("Entry added")
                st.rerun()
            else:
                st.error("Could not add entry")
        else:
            st.error("Invalid format")
