"""Read-only, crash-resilient IMAP archival collector.

The package deliberately implements the IMAP response/literal framing itself
(on top of a plain TCP/TLS socket) so that literal boundaries are driven by the
advertised byte count, never by line-oriented parsing of message bodies.
"""

__version__ = "0.1.0"
