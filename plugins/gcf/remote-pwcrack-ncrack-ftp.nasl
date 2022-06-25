###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-pwcrack-ncrack-ftp.nasl 13607 2019-02-12 14:29:36Z cfischer $
#
# ftp Remote password cracking using ncrack
# svn co svn://svn.insecure.org/nmap-exp/ithilgore/ncrack
# Tested with SVN r14943.
#
# Based on hydra scripts by Michel Arboi <arboi@alussinan.org>
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.80108");
  script_version("$Revision: 13607 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 15:29:36 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-10 08:41:48 +0200 (Mon, 10 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("ncrack: ftp");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
  script_family("Brute force attacks");
  script_require_ports("Services/ftp", 21);
  script_dependencies("toolcheck.nasl", "gcf/remote-pwcrack-options.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_mandatory_keys("Tools/Present/ncrack", "Secret/pwcrack/logins_file", "Secret/pwcrack/passwords_file");

  script_tag(name:"summary", value:"This plugin runs ncrack to find ftp accounts & passwords by brute force.");

  script_tag(name:"solution", value:"Set a secure password for the mentioned account(s).");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ftp_func.inc");

logins = get_kb_item("Secret/pwcrack/logins_file");
passwd = get_kb_item("Secret/pwcrack/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_ftp_port(default:21);

timeout = get_kb_item("/tmp/pwcrack/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/pwcrack/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/pwcrack/empty_password");
login_pass = get_kb_item("/tmp/pwcrack/login_password");
exit_asap = get_kb_item("/tmp/pwcrack/exit_ASAP");

dstaddr=get_host_ip();

i = 0;
argv[i++] = "ncrack";
argv[i++] = "-U"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;

hostpart = "ftp://"+dstaddr+":"+port;

if (timeout > 0)
{
	hostpart=hostpart+",to="+timeout;
}

if (tasks > 0)
{
	hostpart=hostpart+",CL="+tasks;
}

argv[i++] = hostpart;

report = "";
results = pread(cmd: "ncrack", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: dstaddr+" "+port+"/tcp *ftp: *(.*) (.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'pwcrack/ftp/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_message(port: port,
    data: 'ncrack was able to break the following ftp accounts:\n' + report);
