DIRECTORYS = userApp firewall_module

.PHONY:all install clean

all:
	@for dir in $(DIRECTORYS); do\
		$(MAKE) -C $$dir; \
	done

install:
	@for dir in $(DIRECTORYS); do\
		$(MAKE) -C $$dir install; \
	done

clean:
	@for dir in $(DIRECTORYS); do\
		$(MAKE) -C $$dir clean; \
	done