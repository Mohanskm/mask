import spacy
import json
import re
import hashlib
import os

# Load spaCy model with improved entity recognition
try:
    nlp = spacy.load("en_core_web_lg")  # Using the larger model for better entity recognition
except OSError:
    print("Note: Using small model as large model not available. For better results install with: python -m spacy download en_core_web_lg")
    nlp = spacy.load("en_core_web_sm")

def get_mapping_filename(email_id):
    """Generate a unique filename for each email's mapping"""
    return f"entity_mapping_{email_id}.json"

def mask_email(email_text, email_id=None):
    """
    Mask sensitive entities in an email while preserving intent.
    
    Args:
        email_text: The email text to mask
        email_id: Optional unique identifier for the email
    
    Returns:
        Masked email text and the email_id used for mapping
    """
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
    
    # First pass: collect all entities to mask
    entities_to_mask = []
    for ent in doc.ents:
        if ent.label_ in entity_types:
            entities_to_mask.append((ent.text, ent.start_char, ent.end_char, ent.label_))
    
    # Sort by length in descending order to prevent partial replacements
    entities_to_mask.sort(key=lambda x: len(x[0]), reverse=True)
    
    # Process entities to mask
    for ent_text, start_char, end_char, label in entities_to_mask:
        # Skip if this span overlaps with an already masked one
        if any(start_char < end and end_char > start for start, end in masked_spans):
            continue
            
        placeholder = f"[{label}_{len(entity_map) + 1}]"
        entity_map[placeholder] = ent_text
        
        # Replace all occurrences of this specific entity
        masked_email = masked_email.replace(ent_text, placeholder)
        
        # Mark as masked
        masked_spans.append((start_char, end_char))
    
    # Mask email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails_found = re.findall(email_pattern, masked_email)
    for i, email_addr in enumerate(emails_found):
        placeholder = f"[EMAIL_{i + 1}]"
        entity_map[placeholder] = email_addr
        masked_email = masked_email.replace(email_addr, placeholder)
    
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
    
    # Mask URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls_found = re.findall(url_pattern, masked_email)
    for i, url in enumerate(urls_found):
        placeholder = f"[URL_{i + 1}]"
        entity_map[placeholder] = url
        masked_email = masked_email.replace(url, placeholder)
    
    # Mask file attachments references
    attachment_patterns = [
        r"attached (?:file|document|spreadsheet|presentation|pdf)",
        r"attachment[s]?",
        r"\.pdf",
        r"\.docx?",
        r"\.xlsx?",
        r"\.pptx?"
    ]
    
    for i, pattern in enumerate(attachment_patterns):
        for match in re.finditer(pattern, masked_email, re.IGNORECASE):
            found_text = match.group()
            placeholder = f"[ATTACHMENT_{i}_{len(entity_map) + 1}]"
            entity_map[placeholder] = found_text
            masked_email = masked_email.replace(found_text, placeholder)
    
    # Save mapping with unique filename
    mapping_filename = get_mapping_filename(email_id)
    with open(mapping_filename, "w") as f:
        json.dump(entity_map, f, indent=4)
    
    return masked_email, email_id

def unmask_email(masked_email, email_id):
    """
    Restore original email using the stored mapping.
    
    Args:
        masked_email: The masked email text
        email_id: The unique identifier for the email
        
    Returns:
        The unmasked email text
    """
    mapping_filename = get_mapping_filename(email_id)
    
    try:
        with open(mapping_filename, "r") as f:
            entity_map = json.load(f)
        
        unmasked_email = masked_email
        
        # Sort placeholders by length in descending order to prevent partial replacements
        placeholders = sorted(entity_map.keys(), key=len, reverse=True)
        
        # Replace placeholders with actual values
        for placeholder in placeholders:
            unmasked_email = unmasked_email.replace(placeholder, entity_map[placeholder])
        
        return unmasked_email
    except FileNotFoundError:
        return f"Error: Mapping file '{mapping_filename}' not found."

def batch_process_emails(emails):
    """Process a batch of emails with masking and unmasking"""
    results = []
    
    for i, email in enumerate(emails, start=1):
        email_id = f"email_{i}"
        
        # Mask the email
        masked_email, email_id = mask_email(email, email_id)
        
        # Unmask the email
        unmasked_email = unmask_email(masked_email, email_id)
        
        # Calculate masking effectiveness
        total_chars = len(email)
        masked_chars = sum(1 for a, b in zip(email, masked_email) if a != b)
        masking_percentage = (masked_chars / total_chars) * 100 if total_chars > 0 else 0
        
        results.append({
            "email_id": email_id,
            "original_length": len(email),
            "masked_length": len(masked_email),
            "masking_percentage": f"{masking_percentage:.1f}%",
            "masked_email": masked_email,
            "unmasked_email": unmasked_email,
            "perfect_unmask": email == unmasked_email
        })
    
    return results

# Sample emails from original code
emails = [
    """Dear Manisha,

I sent you the attached email on Sunday(2024.11.24).
Ramona Salamat Pars is waiting for this file to complete their documents.

We are under pressure, please understand us and push the manufacturer.

Best Regards;
Maryam Ghasemi
Commercial Department
Mahan Pharmed Chem. Co. (MPC Co)""",

    """Dear Naveen,

Please find the customer's comment below;

Quote

Following below email and yesterday tele conversation; You are kindly requested to provide us with Liposomal Ferrous Bisglycinate MOA corrected document; I got your explanation however our R&D people requested for corrected document from supplier side; It is necessary and important for us;

Unquote

IT'S SO URGENT FOR RAMONA SALAMAT PARS.

Best Regards;
Maryam Ghasemi
Commercial Department
Mahan Pharmed Chem. Co. (MPC Co)

Tel: +98 2144382191
Mobile: + 98 919 7689076"""
]

# Test the improved system
results = batch_process_emails(emails)

# Output results
print("\n=== EMAIL MASKING RESULTS ===\n")
for i, result in enumerate(results, start=1):
    print(f"Email {i} (ID: {result['email_id']})")
    print(f"Original length: {result['original_length']} characters")
    print(f"Masked length: {result['masked_length']} characters")
    print(f"Masking rate: {result['masking_percentage']}")
    print(f"Perfect unmask: {'Yes' if result['perfect_unmask'] else 'No'}")
    print("\nMasked Email:")
    print(result['masked_email'])
    print("\nUnmasked Email:")
    print(result['unmasked_email'])
    print("\n" + "="*50 + "\n")