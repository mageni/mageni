###############################################################################
# OpenVAS Vulnerability Test
#
# IIS Possible Compromise
#
# Authors:
# H D Moore <hdm@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11003");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_name("IIS Possible Compromise");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
  script_family("Malware");
  script_dependencies("gb_get_http_banner.nasl", "DDI_Directory_Scanner.nasl", "webmirror.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Investigate the discovered files.");

  script_tag(name:"summary", value:"One or more files were found on this host that
  indicate a possible compromise.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if(!banner || "IIS" >!< banner )
  exit( 0 );

function check(url, arg, pat) {

  local_var str, r;

  str = http_get(item:string(url, arg), port:port);

  r = http_keepalive_send_recv(port:port, data:str);
  if(!r)
    exit(0);

  # cache files that don't exist
  if(ereg(pattern:"HTTP/1\.[01] 40[34] ", string:r)) {
    add_cache(url:url);
    return FALSE;
  }

  if (egrep(string:r, pattern:pat)) {
    return TRUE;
  }
  return FALSE;
}

function headcheck(req) {

  local_var str, r;

  str = http_head(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:str);
  if(!r)
    exit(0);

  if(ereg(pattern:"^HTTP/1\.[01] (2|502) ", string:r)) {
    return TRUE;
  }
  return FALSE;
}

function dllcheck(req) {

  local_var str, r;

  str = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:str);
  if(!r)
    exit(0);

  # cache missing dll's
  if ("module could not be found" >< r)
    add_cache(url:req);

  if ("procedure could not be found" >< r) {
    return TRUE;
  }
  return FALSE;
}

# this exploit hijacks the socket used to make the
# web request, spawning a command shell over it, so we
# can't use the normal detection methods
function iisecheck(req) {

  local_var str, soc, r, r2;

  str = http_get(item:req, port:port);
  soc = http_open_socket(port);
  if(!soc)
    return FALSE;

  send(socket:soc, data:str);
  r = recv_line(socket:soc, length:1024);
  if(egrep(pattern:"We Got It", string:r)) {
    send(socket:soc, data:string("\r\n\r\nexit\r\n\r\n"));
    http_close_socket(soc);
    return TRUE;
  } else {
    r2 = http_recv(socket:soc);
    if( ereg(pattern:"HTTP/1\.[01] 40[34] ", string:r) ||
        egrep(pattern:"module could not be found", string:r2)) {
      add_cache(url:req);
      http_close_socket(soc);
      return FALSE;
    }
  }
  http_close_socket(soc);
  return(FALSE);
}

# directory list management
dirs[0] = "/";
num_dirs = 0;

function initialize_dirs () {

  local_var _dir_idx, d;

  _dir_idx = 0;

  foreach d( make_list_unique( "/scripts", "/msadc", cgi_dirs( port:port ) ) ) {
    add_dir_list(dir:d);
    _dir_idx = _dir_idx + 1;
  }
  return(_dir_idx);
}

function check_dir_list (dir) {

  local_var CDL;

  for(CDL=0; dirs[CDL]; CDL++) {
    if(dirs[CDL] == dir)
      return(1);
  }
  return(0);
}

function add_dir_list (dir) {
  if(check_dir_list(dir:dir) == 0) {
    dirs[num_dirs] = dir;
    num_dirs = num_dirs + 1;
  }
}

# cached url list management
cache[0] = 0;
num_cache = 0;

function check_cache (url) {

  local_var CLI;

  for (CLI=0; cache[CLI]; CLI++) {
    if(cache[CLI] == url)
      return(1);
  }
  return(0);
}

function add_cache(url) {
  if (check_cache(url:url) == 0) {
    cache[num_cache] = url;
    num_cache = num_cache + 1;
    return(1);
  }
  return(0);
}

# report management
reported_urls[0] = 0;
reported_urls_cnt = 0;

reported_tests[0] = 0;

report_header = "";
report_footer = "";

function reported(url) {

  local_var found_it, rep_idx;

  found_it = 0;
  for (rep_idx=0; rep_idx <reported_urls_cnt; rep_idx++) {
    if(reported_urls[rep_idx] == url) {
      return(1);
    }
  }
  reported_urls[reported_urls_cnt] = url;
  reported_urls_cnt = reported_urls_cnt + 1;
}

function add_report(name, url) {
  if(!reported(url:url)) {
    if (reported_tests[name]) {
      # already added report section to the header
    } else {
      report_header = report_header + string(reports[name], "\n\n");
      reported_tests[name] = 1;
    }
    report_footer = report_footer + string(name, " - ", url, "\n");
    report = string(report_header, "\n\nDetails:\n", report_footer);
  }
}

# for convenience
dblquot = raw_string(0x22);

##############
# test index #
##############
tests[0]  = "cmd.exe";
tests[1]  = "nc.exe";
tests[2]  = "iise.exe";
tests[3]  = "ftp.exe";
tests[4]  = "pwdump.exe";
tests[5]  = "cmd.asp";
tests[6]  = "upload.asp";
tests[7]  = "cmd.jsp";
tests[8]  = "radmin";
tests[9]  = "dtreg.exe";
tests[9]  = "kill.exe";
tests[10] = "hk.exe";
tests[11] = "list.exe";
tests[12] = "newgina.dll";
tests[13] = "iiscrack.dll";
tests[14] = "vnc";
tests[15] = "pwdump2.exe";
tests[16] = "pwdump3.exe";
tests[17] = "servuftpd";
tests[18] = "info.exe";
tests[19] = "whoami.exe";
tests[20] = "ipconfig.exe";
tests[21] = "fscan.exe";
tests[22] = "hunt.exe";

################
# method table #
################
method["cmd.exe"]      = "GET";
method["nc.exe"]       = "GET";
method["iiscrack.dll"] = "GET";
method["ftp.exe"]      = "GET";
method["pwdump.exe"]   = "GET";
method["cmd.asp"]      = "GET";
method["upload.asp"]   = "GET";
method["cmd.jsp"]      = "GET";
method["radmin"]       = "DLL";
method["dtreg.exe"]    = "GET";
method["kill.exe"]     = "GET";
method["hk.exe"]       = "GET";
method["list.exe"]     = "GET";
method["newgina.dll"]  = "DLL";
method["iise.exe"]     = "IISE"; # this one needs its own method
method["vnc"]          = "DLL";
method["pwdump2.exe"]  = "DLL";
method["pwdump3.exe"]  = "DLL";
method["servuftpd"]    = "DLL";
method["info.exe"]     = "GET";
method["whoami.exe"]   = "GET";
method["ipconfig.exe"] = "GET";
method["fscan.exe"]    = "GET";
method["hunt.exe"]     = "GET";

###################
# arguments table #
###################
args["cmd.exe"]      = "?/c+dir+c:\\+/OG";
args["nc.exe"]       = "?-h";
args["iiscrack.dll"] = "";
args["ftp.exe"]      = "?/c+-h";
args["pwdump.exe"]   = "?-h";
args["cmd.asp"]      = "";
args["upload.asp"]   = "";
args["cmd.jsp"]      = "";
args["radmin"]       = "";
args["dtreg.exe"]    = "";
args["kill.exe"]     = "";
args["hk.exe"]       = "?boom";
args["list.exe"]     = "";
args["newgina.dll"]  = "";
args["iise.exe"]     = "";
args["vnc"]          = "";
args["pwdump2.exe"]  = "";
args["pwdump3.exe"]  = "";
args["servuftpd"]    = "";
args["info.exe"]     = "";
args["whoami.exe"]   = "?/h";
args["ipconfig.exe"] = "?/h";
args["fscan.exe"]    = "";
args["hunt.exe"]     = "?/h";


##################
# patterns table #
##################
pats["cmd.exe"]      = "<DIR>";
pats["nc.exe"]       = "this cruft";
pats["iiscrack.dll"] = "www\.digitaloffense\.net|Default MFC Web Server Extension";
pats["ftp.exe"]      = "Suppresses display of remote server";
pats["pwdump.exe"]   = "You must be running as user|Pwdump2 - dump|software based on pwdump2";
pats["cmd.asp"]      = "\.CMD";
pats["upload.asp"]   = string("type=", dblquot, "file", dblquot);
pats["cmd.jsp"]      = "COMMANDLINE";
pats["radmin"]       = "";
pats["dtreg.exe"]    = "Syntax: DtReg";
pats["kill.exe"]     = "missing pid or task name";
pats["hk.exe"]       = "lsass pid";
pats["list.exe"]     = "System Process";
pats["newgina.dll"]  = "";
pats["iise.exe"]     = "";
pats["vnc"]          = "";
pats["pwdump2.exe"]  = "";
pats["pwdump3.exe"]  = "";
pats["servuftpd"]    = "";
pats["info.exe"]     = "Server Information";
pats["whoami.exe"]   = "Display all information in the current access";
pats["ipconfig.exe"] = "Release the IP address";
pats["fscan.exe"]    = "no port scanning ";
pats["hunt.exe"]     = "SMB share enumerator";


##############
# file table #
##############
files["cmd.exe_0"]  = "cmd.exe";
files["cmd.exe_1"]  = "root.exe";
files["cmd.exe_2"]  = "bin.exe";
files["cmd.exe_3"]  = "shell.exe";
files["cmd.exe_4"]  = "hack.exe";
files["cmd.exe_5"]  = "1.exe";
files["cmd.exe_6"]  = "2.exe";
files["cmd.exe_7"]  = "3.exe";
files["cmd.exe_8"]  = "4.exe";
files["cmd.exe_9"]  = "bip.exe";
files["cmd.exe_9"]  = "stromake.exe";
files["cmd.exe_10"] = "superlol.exe";
files["cmd.exe_11"] = "cmd1.exe";
files["cmd.exe_12"] = "az.exe";
files["cmd.exe_13"] = "ft.exe";
files["cmd.exe_14"] = "inuse.exe";
files["cmd.exe_15"] = "mx.exe";
files["cmd.exe_16"] = "sensepost.exe";
files["cmd.exe_17"] = "blackbeard.exe";
files["cmd.exe_18"] = "spooler.exe";
files["cmd.exe_19"] = "sklp.exe";
files["cmd.exe_20"] = "rooter.exe";
files["cmd.exe_21"] = "sys.exe";
files["cmd.exe_22"] = "test.exe";
files["cmd.exe_23"] = "gogo.exe";
files["cmd.exe_24"] = "exchange.exe";

files["nc.exe_0"]   = "nc.exe";
files["nc.exe_1"]   = "ncx.exe";
files["nc.exe_2"]   = "netcat.exe";
files["nc.exe_3"]   = "dllhosts.exe";

files["iise.exe_0"]  = "iise.dll";
files["iise.exe_1"]  = "httpodbc.dll";
files["iise.exe_2"]  = "idq.dll";
files["iise.exe_3"]  = "httpext.dll";
files["iise.exe_4"]  = "ssinc.dll";
files["iise.exe_5"]  = "msw3prt.dll";
files["iise.exe_6"]  = "author.dll";
files["iise.exe_7"]  = "admin.dll";
files["iise.exe_8"]  = "shtml.dll";
files["iise.exe_9"]  = "sspifilt.dll";
files["iise.exe_10"] = "compfilt.dll";
files["iise.exe_11"] = "pwsdata.dll";
files["iise.exe_12"] = "md5filt.dll";
files["iise.exe_13"] = "fpexedll.dll";
files["iise.dll_14"] = "http.dll";
files["iise.dll_15"] = "httpodbc2.dll";
files["iise.dll_16"] = "iisadmin.dll";
files["iise.dll_17"] = "river.dll";
files["iise.dll_18"] = "dumdedum.dll";
files["iise.dll_19"] = "iishelp.dll";
files["iise.dll_20"] = "htadm.dll";
files["iise.dll_21"] = "crack.dll";
files["iise.dll_22"] = "nsiislog.dll";
files["iise.dll_23"] = "hh.dll";
files["iise.dll_24"] = "fpexe.dll";
files["iise.dll_25"] = "1.dll";
files["iise.dll_26"] = "red.dll";
files["iise.dll_27"] = "popper.dll";
files["iise.dll_28"] = "iiscrack-upx.dll";


files["iiscrack.dll_0"]  = "iiscrack.dll";
files["iiscrack.dll_1"]  = "httpodbc.dll";
files["iiscrack.dll_2"]  = "idq.dll";
files["iiscrack.dll_3"]  = "httpext.dll";
files["iiscrack.dll_4"]  = "ssinc.dll";
files["iiscrack.dll_5"]  = "msw3prt.dll";
files["iiscrack.dll_6"]  = "author.dll";
files["iiscrack.dll_7"]  = "admin.dll";
files["iiscrack.dll_8"]  = "shtml.dll";
files["iiscrack.dll_9"]  = "sspifilt.dll";
files["iiscrack.dll_10"] = "compfilt.dll";
files["iiscrack.dll_11"] = "pwsdata.dll";
files["iiscrack.dll_12"] = "md5filt.dll";
files["iiscrack.dll_13"] = "fpexedll.dll";
files["iiscrack.dll_14"] = "http.dll";
files["iiscrack.dll_15"] = "httpodbc2.dll";
files["iiscrack.dll_16"] = "iisadmin.dll";
files["iiscrack.dll_17"] = "river.dll";
files["iiscrack.dll_18"] = "dumdedum.dll";
files["iiscrack.dll_19"] = "iishelp.dll";
files["iiscrack.dll_20"] = "htadm.dll";
files["iiscrack.dll_21"] = "crack.dll";
files["iiscrack.dll_22"] = "nsiislog.dll";
files["iiscrack.dll_23"] = "hh.dll";
files["iiscrack.dll_24"] = "fpexe.dll";
files["iiscrack.dll_25"] = "1.dll";
files["iiscrack.dll_26"] = "red.dll";
files["iiscrack.dll_27"] = "popper.dll";
files["iiscrack.dll_28"] = "iiscrack-upx.dll";

files["ftp.exe_0"] = "ftp.exe";
files["ftp.exe_1"] = "ftpx.exe";
files["ftp.exe_2"] = "1.exe";
files["ftp.exe_3"] = "2.exe";
files["ftp.exe_4"] = "3.exe";
files["ftp.exe_5"] = "4.exe";

files["pwdump.exe_0"] = "pwdump.exe";
files["pwdump.exe_1"] = "pwdump2.exe";
files["pwdump.exe_2"] = "pwdump3.exe";

files["cmd.asp_0"] = "cmdasp.asp";
files["cmd.asp_1"] = "cmd.asp";
files["cmd.asp_2"] = "shell.asp";
files["cmd.asp_3"] = "own.asp";
files["cmd.asp_4"] = "0wn.asp";
files["cmd.asp_5"] = "exec.asp";
files["cmd.asp_6"] = "x.asp";

files["upload.asp_0"] = "upload.asp";
files["upload.asp_1"] = "uploadx.asp";
files["upload.asp_2"] = "up.asp";
files["upload.asp_3"] = "file.asp";
files["upload.asp_4"] = "fx.asp";

files["cmd.jsp_0"] = "cmd.jsp";
files["cmd.jsp_1"] = "shell.jsp";
files["cmd.jsp_2"] = "own.jsp";
files["cmd.jsp_3"] = "hack.jsp";
files["cmd.jsp_4"] = "exec.jsp";

files["radmin_0"] = "admdll.dll";
files["radmin_1"] = "raddrv.dll";

files["dtreg.exe_0"] = "dtreg.exe";

files["kill.exe_0"] = "kill.exe";
files["kill.exe_1"] = "tkill.exe";
files["kill.exe_2"] = "pskill.exe";

files["hk.exe_0"] = "hk.exe";

files["list.exe_0"] = "list.exe";
files["list.exe_1"] = "tlist.exe";
files["list.exe_2"] = "plist.exe";

files["newgina.dll_0"] = "newgina.dll";

files["vnc_0"] = "vnchooks.dll";
files["vnc_1"] = "omnithread_rt.dll";

files["pwdump2.exe_0"] = "samdump.dll";

files["pwdump3.exe_0"] = "lsaext.dll";

files["servuftpd_0"] = "jasfv.dll";

files["info.exe_0"] = "info.exe";

files["whoami.exe_0"] = "whoami.exe";

files["ipconfig.exe_0"] = "ipconfig.exe";

files["fscan.exe_0"] = "fscan.exe";

files["hunt.exe_0"] = "hunt.exe";

reports["cmd.exe"]      = "One or more copies of the Windows command interpreter were found, it can be used to execute arbitrary commands on this server through the web.";
reports["nc.exe"]       = "One or more copies of the 'netcat.exe' tool were found, it can be used to either listen for or establish network connections, it includes the ability to run an arbitrary command across that connection.";
reports["iiscrack.dll"] = "One or more copies of the 'iiscrack.dll' exploit were found, it is used to gain SYSTEM privileges on a web server already compromised through another method.";
reports["ftp.exe"]      = "One or more copies of the Windows command line FTP utility were found, it is often left in the web root as part of an automated attack.";
reports["pwdump.exe"]   = "One or more copies of 'pwdump' were found,it is used to dump the encrypted password hashes from a Windows server.";
reports["cmd.asp"]      = "One or more copies of the 'cmd.asp' script were found, this ASP script can be used to execute commands over the web, on IIS 4.0 it executes with SYSTEM privileges.";
reports["upload.asp"]   = "One or more copies of the 'upload.asp' script were found, this ASP script can be used to upload files to the server over the web, often used by attackers when the target is firewalled.";
reports["cmd.jsp"]      = "One or more copies of the 'jsp.cmd' script were found, this JSP script can be used to execute commands over the web.";
reports["radmin"]       = "One more DLL files were found which indicate the presence of the 'Remote Administrator' tool. This tool is used to gain remote access to a compromised server.";
reports["dtreg.exe"]    = "One or more copies of the 'dtreg.exe' executable were found, this tool is used to edit the registry, often included in batch scripts which install a backdoor.";
reports["kill.exe"]     = "One or more copies of the 'kill.exe' executable were found, this tool is used for terminating processes, it was originally bundled with the Windows Resource Kits and has become a favorite of attackers.";
reports["hk.exe"]       = "One or more copies of the 'hk.exe' exploit were found, it is used to gain SYSTEM privileges on a web server already compromised through another method.";
reports["list.exe"]     = "One or more copies of the 'list.exe' executable were found, this tool is used for enumerating processes, it was originally bundled with the Windows Resource Kits and has become a favorite of attackers.";
reports["newgina.dll"]  = "One more DLL files were found which appear to be part of the 'NewGina.dll' password logging toolkit.";
reports["iise.exe"]     = "One or more copies of the server-side component of the 'iise.exe' exploit were found, it is used to gain a remote command shell with SYSTEM privileges over the web port.";
reports["vnc"]          = "One more DLL files were found which indicate the presence of the 'VNC' remote administration utility.";
reports["pwdump2.exe"]  = "One more DLL files were found which indicate the presence of the 'pwdump2.exe' password hash dumping tool.";
reports["pwdump3.exe"]  = "One more DLL files were found which indicate the presence of the 'pwdump3.exe' password hash dumping tool.";
reports["servuftpd"]    = "One more DLL files were found which indicate the presence of the 'ServUFTPD' FTP server, commonly used by attackers to setup rogue FTP services on compromised hosts.";
reports["info.exe"]     = "One more copies of the 'info.exe' tool were found, this CGI application provides a large amount of information about the server remotely and is often installed by attackers.";
reports["whoami.exe"]   = "One more copies of the 'whoami.exe' tool were found, this application displays the user account it is run by and is often installed by attackers.";
reports["ipconfig.exe"] = "One more copies of the 'ipconfig.exe' tool were found, this application is used to manage network settings and is often copied into the web root by attackers.";
reports["hunt.exe"]     = "One more copies of the 'hunt.exe' tool were found, this application is used to scan for network shares and is often installed by attackers.";
reports["fscan.exe"]    = "One more copies of the 'fscan.exe' tool were found, this application is used to run port scans from the command line and is often installed by attackers.";

report = "";

initialize_dirs();

# prevent false positives
ValidHead = 1;
if(headcheck(req:"/CompromisedScan.dll"))
  ValidHead = 0;

ValidDLL = 1;
if(dllcheck(req:"/CompromisedScan.dll"))
  ValidDLL = 0;

# the main loop
for(x = 0; tests[x]; x++) {

  cur_test = tests[x];
  cur_meth = method[cur_test];
  cur_args = args[cur_test];
  cur_pat  = pats[cur_test];

  for(d = 0; dirs[d]; d++) {
    stop = 0;
    for(f = 0; stop == 0; f++) {
      filename = files[string(cur_test, "_", f)];
      if(filename) {
        if (dirs[d] == "/") {
          url = string("/", filename);
        } else {
          url = string(dirs[d], "/", filename);
        }

        if(!check_cache(url:url)) {
          if(cur_meth == "GET") {
            if(check(url:url, arg:cur_args, pat:cur_pat)) {
              add_report(name:cur_test, url:url);
              add_cache(url:url);
            }
          }

          if((ValidHead == 1) && (cur_meth == "HEAD")) {
            if(headcheck(req:url)) {
              add_report(name:cur_test, url:url);
              add_cache(url:url);
            }
          }

          if((ValidDLL == 1) && (cur_meth == "DLL")) {
            if (dllcheck(req:url)) {
              add_report(name:cur_test, url:url);
              add_cache(url:url);
            }
          }

          if(cur_meth == "IISE") {
            if(iisecheck(req:url)) {
              add_report(name:cur_test, url:url);
              add_cache(url:url);
            }
          }
        }
      } else {
        stop = 1;
      }
    }
  }
}

if(strlen(report)) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);