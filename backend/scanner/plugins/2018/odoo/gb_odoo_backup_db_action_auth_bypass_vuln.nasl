###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_odoo_backup_db_action_auth_bypass_vuln.nasl 13133 2019-01-18 04:50:16Z ckuersteiner $
#
# Odoo 'Backup Database Action' Authentication Bypass Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:odoo:odoo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812757");
  script_version("$Revision: 13133 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 05:50:16 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-02-08 13:00:22 +0530 (Thu, 08 Feb 2018)");

  script_name("Odoo 'Backup Database Action' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This VT has been deprecated since CVE-2018-6620 has been rejected.

  The host is running Odoo software and is
  prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request
  and check whether it is able to backup websites databases directly with
  no authorized accounts.");

  script_tag(name:"insight", value:"The flaw exists as Odoo does not require
  authentication to be configured for a 'Backup Database' action.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to backup websites databases directly with no authenticated accounts.");

  script_tag(name:"affected", value:"Odoo Management Software.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://asdedc.bid/odoo.html");
  script_xref(name:"URL", value:"https://www.odoo.com");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_odoo_remote_detect.nasl");
  script_mandatory_keys("Odoo/Detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!odPort = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:odPort))
  exit(0);

if( dir == "/" ) dir = "";

url = dir + '/web/database/manager#action=database_manager';

if (http_vuln_check(port:odPort, url:url , pattern: '<title>Odoo</title>',
                    extra_check:make_list('Create Database', 'Set Master Password', '>Backup Database<', '>Restore Database<'),
                    check_header: TRUE)) {
  report = report_vuln_url(port:odPort, url:url);
  security_message(port:odPort, data:report);
  exit(0);
}

exit(99);
