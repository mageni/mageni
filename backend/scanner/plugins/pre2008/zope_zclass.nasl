# OpenVAS Vulnerability Test
# Description: Zope ZClass Permission Mapping Bug
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10777");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0567");
  script_name("Zope ZClass Permission Mapping Bug");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zope/banner");

  script_tag(name:"solution", value:"Upgrade to Zope 2.3.3 or apply the hotfix referenced in the vendor
  advisory above.");

  script_tag(name:"summary", value:"The remote web server uses a version of Zope which is older than
  version 2.3.3. In such versions, any user can visit a ZClass declaration and change the ZClass
  permission mappings for methods and other objects defined within the ZClass, possibly allowing for
  unauthorized access within the Zope instance.");

  script_xref(name:"URL", value:"http://www.zope.org/Products/Zope/Hotfix_2001-05-01/security_alert");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Zope" >!< banner)
  exit(0);

if(egrep(pattern:"Server: .*Zope 2\.((0\..*)|(1\..*)|(2\..*)|(3\.[0-2]))", string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);