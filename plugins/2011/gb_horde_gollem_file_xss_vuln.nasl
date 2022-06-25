###############################################################################
# OpenVAS Vulnerability Test
#
# Horde Gollem 'file' Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801870");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-3447");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Horde Gollem 'file' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://bugs.horde.org/ticket/9191");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41624");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2523");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_horde_gollem_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/gollem/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Horde Gollem versions before 1.1.2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'file' parameter to 'view.php', which allows attackers to execute arbitrary
  HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Horde Gollem version 1.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running Horde Gollem and is prone to cross site
  scripting vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"gollem"))
{
  if(version_is_less(version:vers, test_version:"1.1.2")){
    security_message(port:port);
  }
}
