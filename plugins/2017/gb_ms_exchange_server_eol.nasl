###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_exchange_server_eol.nasl 11835 2018-10-11 08:38:49Z mmartin $
#
# Microsoft Exchange Server End Of Life Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108202");
  script_version("$Revision: 11835 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 10:38:49 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-07 08:00:00 +0200 (Mon, 07 Aug 2017)");
  script_name("Microsoft Exchange Server End Of Life Detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ms_exchange_server_detect.nasl", "gb_windows_cpe_detect.nasl");
  script_mandatory_keys("MS/Exchange/Server/installed");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/lifecycle/search?alpha=Exchange%20Server");
  script_xref(name:"URL", value:"https://support.office.com/en-us/article/Exchange-2007-End-of-Life-Roadmap-c3024358-326b-404e-9fe6-b618e54d977d");

  script_tag(name:"summary", value:"The Microsoft Exchange Server version on the remote host has reached the end of life and should
  not be used anymore.");
  script_tag(name:"impact", value:"An end of life version of Microsoft Exchange Server is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");
  script_tag(name:"solution", value:"Update the Microsoft Exchange Server version on the remote host to a newer version of Exchange on your on-premises servers or migrate to Office 365 using cutover, staged, or hybrid migration.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = build_eol_message( name:"Microsoft Exchange Server",
                              cpe:CPE,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
