###############################################################################
# OpenVAS Vulnerability Test
# $Id: amap.nasl 14129 2019-03-13 07:40:32Z cfischer $
#
# amap (NASL wrapper)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14663");
  script_version("$Revision: 14129 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 08:40:32 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("amap (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Port scanners");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/amap", "Tools/Present/amap/bin");

  script_add_preference(name:"File containing machine readable results : ", type:"file", value:"");
  script_add_preference(name:"Mode", type:"radio", value:"Map applications;Just grab banners;Port scan only");
  script_add_preference(name:"Quicker", type:"checkbox", value:"no");
  script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value:"no");
  script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value:"yes");
  script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value:"yes");
  script_add_preference(name:"Parallel  tasks", type:"entry", value:"");
  script_add_preference(name:"Connection retries", type:"entry", value:"");
  script_add_preference(name:"Connection timeout", type:"entry", value:"");
  script_add_preference(name:"Read timeout", type:"entry", value:"");

  script_tag(name:"summary", value:"This plugin runs amap to find open ports and identify applications.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

tmpnam = NULL;

bin = get_kb_item("Tools/Present/amap/bin");

function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

function on_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++)
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
# No result, launch amap
tmpdir = get_tmp_dir();
if ( ! tmpdir ) exit(0);
tmpnam = strcat(tmpdir, "amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediately with a strange error.
 # I let it run just in case some "harmless" probes are added in a
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");

 if (! pr) pr = "1-65535";

 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: bin, argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

 foreach line(split(res))
 {
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
 }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    log_message(port: port, data: "Either this port is dynamically allocated or amap killed this service. If so, upgrade it!\n");
  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   log_message(port: port, proto: proto, data: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);

  #mandatory_key for external_svc_ident.nasl
  set_kb_item( name:"external_svc_ident/available", value:TRUE );
 }
