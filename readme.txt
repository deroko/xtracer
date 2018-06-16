                           xtracer (c) 2008 by deroko of ARTeam
                                
This is tracing driver which uses TLB to trace code execution. Code can
be customized to handle various scenarios. Eg. add more breaks on code
sections, hooking more some native calls to keep control of almost
every allocated buffers, but that's up to the user to implement if he/she
needs it.

This code was writen last year, but since then I didn't publish it...

To use this code simply type:

xtracer.exe <applicaton to trace>

wait a little bit. Also note that you must have internet connection
as code is using my SymbolFinder class to locate some symbols from
ntoskrnl.exe which makes this code compatible with windows versions
from win2k to Vista SP1.

Nothing more to say, enjoy this fine release from ARTeam

                                        (c) 2008 deroko of ARTeam     

Update: sometimes 2018... remove stupid GPLv3, and use MIT...     

Howto build: use old WDK to build xtracer_driver, this was 2008                                   
