################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_laser_printer_2335dn_passwd_disc_vuln.nasl 12308 2018-11-12 03:41:06Z ckuersteiner $
#
# Dell Laser MFP 2335dn Printer Password Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
################################################################################

CPE = "cpe:/h:dell:2335dn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814218");
  script_version("$Revision: 12308 $");
  script_cve_id("CVE-2018-15748");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 04:41:06 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-19 16:18:38 +0530 (Wed, 19 Sep 2018)");
  script_name("Dell Laser MFP 2335dn Printer Password Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Dell Laser MFP 2335dn
  Printer and is prone to a password disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists as any user can retrieve the
  configured SMTP or LDAP password by viewing the HTML source code of the Email
  Settings webpage. Moreover by default printer did not have any admin credentials
  set. Also in some cases, authentication can be achieved with the blank default
  password for the admin account.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Dell 2335dn printers with Printer Firmware
  Version 2.70.05.02, Engine Firmware Version 1.10.65, and Network Firmware Version
  V4.02.15(2335dn MFP) 11-22-2010. Other versions may be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name:"URL", value:"https://www.gerrenmurphy.com/dell-2335dn-password-disclosure");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_dell_laser_printer_detect.nasl");
  script_mandatory_keys("Dell/Laser/MFP/Printer/Running");
  script_require_ports("Services/www", 80);

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if(!http_port = get_app_port( cpe: CPE )) exit(0);

url = "/default.html";
req = http_get_req( port: http_port, url: url);
res = http_keepalive_send_recv( port: http_port, data: req );

if(http_vuln_check(port:http_port, url:url, pattern:"Dell Laser MFP 2335dn", check_header:TRUE,
                   extra_check:make_list('var ldapPassword = "', 'var smtpPassword = "')))
{
  report = report_vuln_url(port:http_port, url: url);
  security_message(data: report, port: http_port);
  exit(0);
}

exit(99);