###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_imp_info_disc_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Horde IMP Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = 'cpe:/a:horde:horde_groupware';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800288");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0463");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde IMP Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://bugs.horde.org/ticket/8836");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-0463");
  script_xref(name:"URL", value:"https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to determine the network
location of the webmail user by logging DNS requests.");

  script_tag(name:"affected", value:"Horde IMP version 4.3.6 and prior.");

  script_tag(name:"insight", value:"The flaw exists when DNS prefetching of domain names contained in links
within e-mail messages.");

  script_tag(name:"solution", value:"Apply the appropriate patch from vendor.");

  script_tag(name:"summary", value:"This host is running Horde IMP and is prone to an information disclosure
vulnerability.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

foreach dir (make_list_unique("/horde/imp", "/Horde/IMP", cgi_dirs(port: port))) {
  rcvRes = http_get_cache(item: dir + "/test.php", port: port);

  if("imp" >< rcvRes || "IMP" >< rcvRes) {
    impVer = eregmatch(pattern:"IMP: H3 .([0-9.]+)" , string:rcvRes);
    if(!isnull(impVer[1])) {
      if (version_is_less_equal(version: impVer[1], test_version: "4.3.6")) {
        security_message(port: port);
        exit(0);
      }
    }
  }
}

exit( 99 );
