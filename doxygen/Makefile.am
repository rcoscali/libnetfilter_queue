if HAVE_DOXYGEN

# Be sure to add new source files to this table
doc_srcs = $(top_srcdir)/src/libnetfilter_queue.c  \
           $(top_srcdir)/src/nlmsg.c               \
           $(top_srcdir)/src/extra/checksum.c      \
           $(top_srcdir)/src/extra/ipv6.c          \
           $(top_srcdir)/src/extra/ipv4.c          \
           $(top_srcdir)/src/extra/tcp.c           \
           $(top_srcdir)/src/extra/udp.c           \
           $(top_srcdir)/src/extra/icmp.c          \
           $(top_srcdir)/src/extra/pktbuff.c

doxyfile.stamp: $(doc_srcs) Makefile.am
	rm -rf html man

# Test for running under make distcheck.
# If so, sibling src directory will be empty:
# move it out of the way and symlink the real one while we run doxygen.
	[ -f ../src/Makefile.in ] || \
{ set -x; cd ..; mv src src.distcheck; ln -s $(top_srcdir)/src; }

	cd ..; doxygen doxygen.cfg >/dev/null

	[ ! -d ../src.distcheck ] || \
{ set -x; cd ..; rm src; mv src.distcheck src; }

# Keep this command up to date after adding new functions and source files.
# The command has to be a single line so the functions work
# (hence ";\" at the end of every line but the last).
	main() { set -e; cd man/man3; rm -f _*;\
setgroup LibrarySetup nfq_open;\
  add2group nfq_close nfq_bind_pf nfq_unbind_pf;\
setgroup Parsing nfq_get_msg_packet_hdr;\
  add2group nfq_get_nfmark nfq_get_timestamp nfq_get_indev nfq_get_physindev;\
  add2group nfq_get_outdev nfq_get_physoutdev nfq_get_indev_name;\
  add2group nfq_get_physindev_name nfq_get_outdev_name;\
  add2group nfq_get_physoutdev_name nfq_get_packet_hw;\
  add2group nfq_get_skbinfo;\
  add2group nfq_get_uid nfq_get_gid;\
  add2group nfq_get_secctx nfq_get_payload;\
setgroup Queue nfq_fd;\
  add2group nfq_create_queue nfq_destroy_queue nfq_handle_packet nfq_set_mode;\
  add2group nfq_set_queue_flags nfq_set_queue_maxlen nfq_set_verdict;\
  add2group nfq_set_verdict2 nfq_set_verdict_batch;\
  add2group nfq_set_verdict_batch2 nfq_set_verdict_mark;\
setgroup ipv4 nfq_ip_get_hdr;\
  add2group nfq_ip_set_transport_header nfq_ip_mangle nfq_ip_snprintf;\
  setgroup ip_internals nfq_ip_set_checksum;\
setgroup ipv6 nfq_ip6_get_hdr;\
  add2group nfq_ip6_set_transport_header nfq_ip6_mangle nfq_ip6_snprintf;\
setgroup nfq_cfg nfq_nlmsg_cfg_put_cmd;\
  add2group nfq_nlmsg_cfg_put_params nfq_nlmsg_cfg_put_qmaxlen;\
setgroup nfq_verd nfq_nlmsg_verdict_put;\
  add2group nfq_nlmsg_verdict_put_mark nfq_nlmsg_verdict_put_pkt;\
setgroup nlmsg nfq_nlmsg_parse;\
  add2group nfq_nlmsg_put;\
setgroup pktbuff pktb_alloc;\
  add2group pktb_data pktb_len pktb_mangle pktb_mangled;\
  add2group pktb_free;\
  setgroup otherfns pktb_tailroom;\
    add2group pktb_mac_header pktb_network_header pktb_transport_header;\
    setgroup uselessfns pktb_push;\
      add2group pktb_pull pktb_put pktb_trim;\
setgroup tcp nfq_tcp_get_hdr;\
  add2group nfq_tcp_get_payload nfq_tcp_get_payload_len;\
  add2group nfq_tcp_snprintf nfq_tcp_mangle_ipv4 nfq_tcp_mangle_ipv6;\
  setgroup tcp_internals nfq_tcp_compute_checksum_ipv4;\
    add2group nfq_tcp_compute_checksum_ipv6;\
setgroup udp nfq_udp_get_hdr;\
  add2group nfq_udp_get_payload nfq_udp_get_payload_len;\
  add2group nfq_udp_mangle_ipv4 nfq_udp_mangle_ipv6 nfq_udp_snprintf;\
  setgroup udp_internals nfq_udp_compute_checksum_ipv4;\
    add2group nfq_udp_compute_checksum_ipv6;\
setgroup Printing nfq_snprintf_xml;\
setgroup icmp nfq_icmp_get_hdr;\
};\
setgroup() { mv $$1.3 $$2.3; BASE=$$2; };\
add2group() { for i in $$@; do ln -sf $$BASE.3 $$i.3; done; };\
main

	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/html
install-data-local:
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3 $(DESTDIR)$(mandir)/man3/

# make distcheck needs uninstall-local
uninstall-local:
	rm -r $(DESTDIR)$(mandir) man html doxyfile.stamp
endif
