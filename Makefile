include $(GOROOT)/src/Make.inc

TARG=mysql-sniffer
CLEANFILES=mysql-sniffer

mysql-sniffer: mysql-sniffer.go
	$(GC) mysql-sniffer.go
	$(LD) -o $@ mysql-sniffer.$(O)
