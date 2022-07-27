###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_archive_tar_26355.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Perl Archive::Tar Module Remote Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/a:perl:archive_tar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100698");
  script_version("$Revision: 13960 $");
  script_bugtraq_id(26355);
  script_cve_id("CVE-2007-4829");
  script_name("Perl Archive::Tar Module Remote Directory Traversal Vulnerability");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_perl_modules_detect_lin.nasl");
  script_mandatory_keys("perl/linux/modules/archive_tar/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/26355");
  script_xref(name:"URL", value:"http://search.cpan.org/~kane/Archive-Tar-1.36/lib/Archive/Tar.pm");
  script_xref(name:"URL", value:"https://issues.rpath.com/browse/RPL-1716?page=com.atlassian.jira.plugin.system.issuetabpanels:all-tabpanel");
  script_xref(name:"URL", value:"http://rt.cpan.org/Public/Bug/Display.html?id=30380");

  script_tag(name:"summary", value:"Perl Archive::Tar module is prone to a directory-traversal
  vulnerability because it fails to validate user-supplied data.");

  script_tag(name:"impact", value:"A successful attack can allow the attacker to overwrite files on a
  computer in the context of the user running the affected application.
  Successful exploits may aid in further attacks.");

  script_tag(name:"affected", value:"Note that all applications using Perl Archive::Tar module may
  be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"1.36" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.36", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );