AI Instructions:
Open PowerShell and verify:
   pandoc --version
Put your .docx in an easy folder
Example: C:\Dissertation\proposal.docx
Convert .docx to Markdown
   In PowerShell:
   cd C:\Dissertation
   pandoc proposal.docx -t gfm -o proposal.md
If your document has images, extract them too
Run:
   pandoc proposal.docx -t gfm --extract-media=media -o proposal.md
This creates a media folder and links images in the markdown.
Open and quickly clean the Markdown
Check headings, tables, references, and equations.
Minor formatting cleanup is normal after conversion.
Share it with me
Place proposal.md in your workspace and tell me the path.
I can then summarize, edit, or align it with your dissertation proposal needs.

If you want, I can also give you a second method that preserves citations better (Pandoc + CSL/BibTeX).