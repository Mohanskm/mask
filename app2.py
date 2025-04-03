import streamlit as st
import spacy
import json
import re
import hashlib
import os
import pandas as pd
from datetime import datetime

# Set page configuration
st.set_page_config(
    page_title="Email Privacy Masker",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state variables if they don't exist
if 'masked_email' not in st.session_state:
    st.session_state.masked_email = ""
if 'unmasked_email' not in st.session_state:  # New variable to store unmasked email
    st.session_state.unmasked_email = ""
if 'display_masked' not in st.session_state:  # New variable to track display state
    st.session_state.display_masked = True
if 'email_id' not in st.session_state:
    st.session_state.email_id = ""
if 'entity_map' not in st.session_state:
    st.session_state.entity_map = {}
if 'masking_stats' not in st.session_state:
    st.session_state.masking_stats = {}
if 'history' not in st.session_state:
    st.session_state.history = []

# Load spaCy model
@st.cache_resource
def load_nlp_model():
    try:
        return spacy.load("en_core_web_lg")
    except OSError:
        st.warning("Using small model as large model not available. For better results install: `python -m spacy download en_core_web_lg`")
        return spacy.load("en_core_web_sm")

nlp = load_nlp_model()

def get_mapping_filename(email_id):
    """Generate a unique filename for each email's mapping"""
    os.makedirs("mappings", exist_ok=True)
    return f"mappings/entity_mapping_{email_id}.json"

def mask_email(email_text, email_id=None):
    """
    Mask sensitive entities in an email while preserving intent.
    
    Args:
        email_text: The email text to mask
        email_id: Optional unique identifier for the email
    
    Returns:
        Masked email text, email_id, entity map, and masking statistics
    """
    start_time = datetime.now()
    doc = nlp(email_text)
    entity_map = {}
    masked_email = email_text
    
    # Generate a unique ID if not provided
    if email_id is None:
        email_id = hashlib.md5(email_text.encode()).hexdigest()[:8]
    
    # Define comprehensive entity types to mask
    entity_types = {
        "PERSON", "ORG", "PRODUCT", "GPE", "DATE", "MONEY", 
        "CARDINAL", "ORDINAL", "QUANTITY", "LOC", "FAC"
    }
    
    # Track already masked entities to avoid partial replacements
    masked_spans = []
    original_entities = {}
    
    # Create a list of phrases that should be protected from masking
    protected_phrases = set()
    
    # First pass: collect all entities to mask from spaCy
    entities_to_mask = []
    for ent in doc.ents:
        if ent.label_ in entity_types:
            entities_to_mask.append((ent.text, ent.start_char, ent.end_char, ent.label_))
            if ent.label_ not in original_entities:
                original_entities[ent.label_] = []
            original_entities[ent.label_].append(ent.text)
    
    # Add salutation detection for names after "Dear"
    salutation_patterns = [
        r'Dear\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
        r'Dear\s+(Mr\.|Mrs\.|Ms\.|Miss|Dr\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
    ]
    
    for pattern in salutation_patterns:
        for match in re.finditer(pattern, email_text):
            if len(match.groups()) == 1:
                # For "Dear Name" pattern
                name_text = match.group(1)
                start_char = match.start(1)
                end_char = match.end(1)
            elif len(match.groups()) == 2:
                # For "Dear Title Name" pattern
                title = match.group(1)
                name = match.group(2)
                name_text = f"{title} {name}"
                start_char = match.start(1)
                end_char = match.end(2)
            else:
                continue
                
            # Check if this name is already identified by spaCy
            if not any(ent_text == name_text for ent_text, _, _, _ in entities_to_mask):
                entities_to_mask.append((name_text, start_char, end_char, "PERSON"))
                if "PERSON" not in original_entities:
                    original_entities["PERSON"] = []
                original_entities["PERSON"].append(name_text)
    
    # Detect signature markers and add them to protected phrases
    signature_markers = [
        r'(?:Thanks|Regards|Sincerely|Best regards|Yours sincerely|Cheers|Best|Yours truly)[,]?',
        r'Thanks & Regards',
    ]
    
    for marker in signature_markers:
        signature_matches = list(re.finditer(marker, email_text, re.IGNORECASE))
        
        for match in signature_matches:
            # Get the signature marker text to ensure we don't mask it
            marker_text = match.group(0)
            protected_phrases.add(marker_text)
            
            # Get everything after the signature marker to the end of the text
            sig_start = match.end()
            signature_block = email_text[sig_start:].strip()
            
            # Split the signature block by whitespace or newlines
            sig_parts = re.split(r'[\s\n]+', signature_block)
            
            for part in sig_parts:
                # Process each word that looks like a name (starts with capital letter)
                if part and re.match(r'^[A-Z][a-z]*$', part):
                    # Find the position of this part in the original text
                    part_start = email_text.find(part, sig_start)
                    if part_start != -1:  # If found
                        part_end = part_start + len(part)
                        
                        # Check if this name is already identified
                        if not any(ent_text == part for ent_text, _, _, _ in entities_to_mask):
                            entities_to_mask.append((part, part_start, part_end, "PERSON"))
                            if "PERSON" not in original_entities:
                                original_entities["PERSON"] = []
                            original_entities["PERSON"].append(part)
    
    # Sort by length in descending order to prevent partial replacements
    entities_to_mask.sort(key=lambda x: len(x[0]), reverse=True)
    
    # Process entities to mask
    for ent_text, start_char, end_char, label in entities_to_mask:
        # Skip if this span overlaps with an already masked one
        if any(start_char < end and end_char > start for start, end in masked_spans):
            continue
        
        # Skip if the entity is a protected phrase like "Thanks & Regards"
        if ent_text in protected_phrases:
            continue
            
        placeholder = f"[{label}_{len(entity_map) + 1}]"
        entity_map[placeholder] = ent_text
        
        # Replace all occurrences of this specific entity
        masked_email = masked_email.replace(ent_text, placeholder)
        
        # Mark as masked
        masked_spans.append((start_char, end_char))
    
    # Mask email addresses, phone numbers, URLs etc. as before...
    # (rest of the function remains the same)
    
    # Mask email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails_found = re.findall(email_pattern, masked_email)
    for i, email_addr in enumerate(emails_found):
        placeholder = f"[EMAIL_{i + 1}]"
        entity_map[placeholder] = email_addr
        masked_email = masked_email.replace(email_addr, placeholder)
        if "EMAIL" not in original_entities:
            original_entities["EMAIL"] = []
        original_entities["EMAIL"].append(email_addr)
    
    # Mask phone numbers with a more comprehensive pattern
    phone_patterns = [
        r"(\+\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",  # +XX (XXX) XXX-XXXX
        r"\+\d{10,15}",  # +XXXXXXXXXXX
        r"\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}"  # XXX-XXX-XXXX
    ]
    
    for i, pattern in enumerate(phone_patterns):
        phone_matches = re.finditer(pattern, masked_email)
        for j, match in enumerate(phone_matches):
            phone = match.group()
            placeholder = f"[PHONE_{i}_{j + 1}]"
            entity_map[placeholder] = phone
            masked_email = masked_email.replace(phone, placeholder)
            if "PHONE" not in original_entities:
                original_entities["PHONE"] = []
            original_entities["PHONE"].append(phone)
    
    # Mask URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls_found = re.findall(url_pattern, masked_email)
    for i, url in enumerate(urls_found):
        placeholder = f"[URL_{i + 1}]"
        entity_map[placeholder] = url
        masked_email = masked_email.replace(url, placeholder)
        if "URL" not in original_entities:
            original_entities["URL"] = []
        original_entities["URL"].append(url)
    
    # Continue with the rest of the function...
    # Save mapping with unique filename
    mapping_filename = get_mapping_filename(email_id)
    with open(mapping_filename, "w") as f:
        json.dump(entity_map, f, indent=4)
    
    # Calculate masking stats
    end_time = datetime.now()
    processing_time = (end_time - start_time).total_seconds()
    total_chars = len(email_text)
    masked_chars = sum(1 for a, b in zip(email_text, masked_email) if a != b)
    masking_percentage = (masked_chars / total_chars) * 100 if total_chars > 0 else 0
    entity_counts = {k: len(v) for k, v in original_entities.items()}
    
    masking_stats = {
        "email_id": email_id,
        "processing_time_seconds": processing_time,
        "original_length": total_chars,
        "masked_length": len(masked_email),
        "masking_percentage": f"{masking_percentage:.1f}%",
        "entity_counts": entity_counts,
        "total_entities_masked": len(entity_map)
    }
    
    return masked_email, email_id, entity_map, masking_stats

def unmask_email(masked_email, email_id=None, entity_map=None):
    """
    Restore original email using the stored mapping.
    
    Args:
        masked_email: The masked email text
        email_id: The unique identifier for the email
        entity_map: Optional entity map to use instead of loading from file
        
    Returns:
        The unmasked email text
    """
    if entity_map is None and email_id is not None:
        mapping_filename = get_mapping_filename(email_id)
        try:
            with open(mapping_filename, "r") as f:
                entity_map = json.load(f)
        except FileNotFoundError:
            return f"Error: Mapping file '{mapping_filename}' not found.", None
    
    if entity_map is None:
        return "Error: No entity mapping provided or found.", None
    
    unmasked_email = masked_email
    
    # Sort placeholders by length in descending order to prevent partial replacements
    placeholders = sorted(entity_map.keys(), key=len, reverse=True)
    
    # Replace placeholders with actual values
    for placeholder in placeholders:
        unmasked_email = unmasked_email.replace(placeholder, entity_map[placeholder])
    
    return unmasked_email, entity_map

def render_entity_mapping_table(entity_map):
    """Convert entity mapping to a DataFrame for display"""
    if not entity_map:
        return pd.DataFrame()
    
    # Extract entity type from the placeholder
    data = []
    for placeholder, original in entity_map.items():
        entity_type = placeholder.split('_')[0].strip('[]')
        data.append({
            "Placeholder": placeholder,
            "Entity Type": entity_type,
            "Original Value": original,
            "Length": len(original)
        })
    
    df = pd.DataFrame(data)
    return df

def add_to_history(action, email_id, text_length):
    """Add an action to the history"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.history.append({
        "timestamp": timestamp,
        "action": action,
        "email_id": email_id,
        "text_length": text_length
    })

# Streamlit UI
st.title("🔒 Email Privacy Masking System")

# Create tabs for different functionalities
tab1, tab2, tab3 = st.tabs(["Mask/Unmask Email", "Entity Mapping", "History"])

with tab1:
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Email Content")
        email_text = st.text_area(
            "Enter email text below:",
            height=300,
            placeholder="Paste your email content here...",
            key="email_input"
        )
    
    with col2:
        st.subheader("Actions")
        
        # Email ID input
        manual_id = st.text_input(
            "Optional Email ID",
            placeholder="Leave blank for auto-generated ID",
            help="Provide an ID to link masked/unmasked emails"
        )
        
        # Mask button
        if st.button("📝 Mask Email", use_container_width=True):
            if email_text:
                email_id = manual_id if manual_id else None
                masked_email, email_id, entity_map, masking_stats = mask_email(email_text, email_id)
                
                st.session_state.masked_email = masked_email
                st.session_state.unmasked_email = email_text  # Store original email
                st.session_state.display_masked = True  # Set display state to masked
                st.session_state.email_id = email_id
                st.session_state.entity_map = entity_map
                st.session_state.masking_stats = masking_stats
                
                add_to_history("Masked", email_id, len(email_text))
                
                st.success(f"Email masked successfully! ID: {email_id}")
            else:
                st.warning("Please enter an email to mask.")
        
        # Unmask button
        if st.button("🔓 Unmask Email", use_container_width=True):
            if st.session_state.masked_email:
                unmasked_email, _ = unmask_email(
                    st.session_state.masked_email,
                    st.session_state.email_id,
                    st.session_state.entity_map
                )
                
                st.session_state.unmasked_email = unmasked_email
                st.session_state.display_masked = False  # Set display state to unmasked
                
                add_to_history("Unmasked", st.session_state.email_id, len(unmasked_email))
                
                st.success("Email unmasked successfully!")
            else:
                st.warning("No masked email available. Please mask an email first.")
        
        # Clear button
        if st.button("🧹 Clear All", use_container_width=True):
            st.session_state.masked_email = ""
            st.session_state.unmasked_email = ""
            st.session_state.display_masked = True
            st.session_state.email_id = ""
            st.session_state.entity_map = {}
            st.session_state.masking_stats = {}
            st.success("All data cleared!")
    
    # Email Display with toggling between masked and unmasked
    if st.session_state.masked_email:
        # Determine what to display based on the display_masked flag
        display_title = "Masked Email" if st.session_state.display_masked else "Unmasked Email"
        display_content = st.session_state.masked_email if st.session_state.display_masked else st.session_state.unmasked_email
        
        st.subheader(display_title)
        
        # Using expander instead of container with border
        email_container = st.expander(f"{display_title} Content", expanded=True)
        with email_container:
            st.code(display_content, language=None)
        
        # Statistics about masking (only show when displaying masked email)
        if st.session_state.masking_stats and st.session_state.display_masked:
            stats = st.session_state.masking_stats
            
            st.subheader("Masking Statistics")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Processing Time", f"{stats['processing_time_seconds']:.3f}s")
            col2.metric("Original Length", stats['original_length'])
            col3.metric("Masked Length", stats['masked_length'])
            col4.metric("Masking Rate", stats['masking_percentage'])
            
            # Entity type breakdown
            if 'entity_counts' in stats and stats['entity_counts']:
                st.subheader("Entities Masked")
                entity_df = pd.DataFrame({
                    'Entity Type': list(stats['entity_counts'].keys()),
                    'Count': list(stats['entity_counts'].values())
                })
                fig_data = entity_df.set_index('Entity Type')
                st.bar_chart(fig_data)

with tab2:
    st.subheader("Entity Mapping Dictionary")
    
    if st.session_state.entity_map:
        # Create a visual representation of the mapping dictionary
        mapping_df = render_entity_mapping_table(st.session_state.entity_map)
        
        # Fix: Use st.dataframe with fixed height to prevent shaking
        st.dataframe(
            mapping_df,
            use_container_width=True,
            hide_index=True,
            height=400  # Add fixed height
        )
        
        # Option to download the mapping as JSON
        if st.download_button(
            label="📥 Download Mapping as JSON",
            data=json.dumps(st.session_state.entity_map, indent=4),
            file_name=f"entity_mapping_{st.session_state.email_id}.json",
            mime="application/json"
        ):
            st.success("Mapping downloaded!")
        
        # Show raw JSON
        with st.expander("View Raw JSON"):
            st.code(json.dumps(st.session_state.entity_map, indent=4), language="json")
    else:
        st.info("No entity mapping available. Please mask an email first.")

with tab3:
    st.subheader("Operation History")
    
    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)
        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )
        
        if st.button("Clear History"):
            st.session_state.history = []
            st.experimental_rerun()
    else:
        st.info("No operation history available.")

# Sidebar with information and settings
with st.sidebar:
    st.title("📋 App Info")
    st.info(
        """
        **Email Privacy Masker** helps you protect sensitive information in emails.
        
        It masks entities like:
        - Names
        - Organizations
        - Dates
        - Locations
        - Phone numbers
        - Email addresses
        - URLs
        - And more!
        """
    )
    
    st.subheader("Current Session")
    if st.session_state.email_id:
        st.success(f"Working with email ID: {st.session_state.email_id}")
    else:
        st.warning("No email currently being processed")
    
    st.subheader("Settings")
    st.checkbox("Mask Dates", value=True, help="Toggle date masking on/off")
    st.checkbox("Mask Locations", value=True, help="Toggle location masking on/off")
    
    # Footer
    st.markdown("---")
    st.caption("© 2025 Email Privacy Tool v1.0")