###############################################################################
# OpenVAS Vulnerability Test
#
# ViewVC Regular Expression Search Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100562");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-31 12:56:41 +0200 (Wed, 31 Mar 2010)");
  script_bugtraq_id(39053);
  script_cve_id("CVE-2010-0132");

  script_name("ViewVC Regular Expression Search Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39053");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-26/");
  script_xref(name:"URL", value:"http://viewvc.tigris.org/source/browse/viewvc/trunk/CHANGES?rev=HEAD");
  script_xref(name:"URL", value:"http://viewvc.org/");
  script_xref(name:"URL", value:"http://viewvc.tigris.org/");

  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("viewvc_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("viewvc/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"ViewVC is prone to a cross-site scripting vulnerability because the
  application fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site and steal cookie-based authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to ViewVC 1.1.5 and 1.0.11 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"viewvc")) {
  if(version_in_range(version: vers, test_version: "1.1", test_version2: "1.1.4") ||
     version_is_less(version: vers, test_version: "1.0.11") ) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);