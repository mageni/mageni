###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_info_disc_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Bugzilla 'localconfig' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801367");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-0180");
  script_bugtraq_id(41144);
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Bugzilla 'localconfig' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40300");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.2.6/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1595");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=561797");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read sensitive configuration
fields.");

  script_tag(name:"affected", value:"Bugzilla version 3.5.1 to 3.6 and 3.7");

  script_tag(name:"insight", value:"The flaw is due to an error in 'install/Filesystem.pm', which uses world
readable permissions for the localconfig files via the database password field and the site_wide_secret field.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Bugzilla version 3.6.1, 3.7.1 or later.");

  script_tag(name:"summary", value:"This host is running Bugzilla and is prone to information disclosure
vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version:vers, test_version:"3.7") ||
    version_in_range(version:vers, test_version: "3.5.1", test_version2:"3.6")) {
  security_message(port:port);
  exit(0);
}

exit(0);
