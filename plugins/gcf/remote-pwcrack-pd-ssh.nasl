###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-pwcrack-pd-ssh.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# SSH Remote password cracking using phrasen|drescher
# http://www.leidecker.info/projects/phrasendrescher/
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
  script_oid("1.3.6.1.4.1.25623.1.0.80106");
  script_version("$Revision: 13568 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-10 08:41:48 +0200 (Mon, 10 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("phrasen|drescher: SSH");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
  script_family("Brute force attacks");
  script_dependencies("toolcheck.nasl", "gcf/remote-pwcrack-options.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("Tools/Present/pd", "Secret/pwcrack/logins_file", "Secret/pwcrack/passwords_file", "ssh/server_banner/available");

  script_tag(name:"summary", value:"This plugin runs phrasen/drescher to find SSH accounts & passwords by brute force.");

  script_tag(name:"solution", value:"Set a secure password for the mentioned account(s).");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssh_func.inc");

logins = get_kb_item("Secret/pwcrack/logins_file");
passwd = get_kb_item("Secret/pwcrack/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_ssh_port(default:22);

timeout = get_kb_item("/tmp/pwcrack/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/pwcrack/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/pwcrack/empty_password");
login_pass = get_kb_item("/tmp/pwcrack/login_password");
exit_asap = get_kb_item("/tmp/pwcrack/exit_ASAP");

dstaddr=get_host_ip();

i = 0;
argv[i++] = "pd";
argv[i++] = "ssh";
argv[i++] = "-P"; argv[i++] = port;
argv[i++] = "-U"; argv[i++] = logins;
argv[i++] = "-d"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}

# not implemented in pd
# if (exit_asap) argv[i++] = "-f";
#

# not implemented in pd
# if (timeout > 0)
# {
# argv[i++] = "-w";
#  argv[i++] = timeout;
# }

if (tasks > 0)
{
  argv[i++] = "-w";
  argv[i++] = tasks;
}

argv[i++] = "-t"; argv[i++] = dstaddr;

report = "";
results = pread(cmd: "pd", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: "password for '(.*)' on "+dstaddr+": *(.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'pwcrack/ssh/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_message(port: port,
    data: 'phrasen|drescher was able to break the following SSH accounts:\n' + report);
