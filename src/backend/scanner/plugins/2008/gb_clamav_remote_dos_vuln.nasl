###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_remote_dos_vuln.nasl 12667 2018-12-05 12:55:38Z cfischer $
#
# ClamAV get_unicode_name() Off-By-One Heap Based BOF Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800067");
  script_version("$Revision: 12667 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 13:55:38 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5050");
  script_bugtraq_id(32207);
  script_name("ClamAV get_unicode_name() Off-By-One Heap based BOF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_lin.nasl", "gb_clamav_detect_win.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("ClamAV/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32663");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46462");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/3085");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=637952;group_id=86638");

  script_tag(name:"impact", value:"A specially crafted VBA project when opened causes heap buffer overflow
  which can be exploited by attackers to execute arbitrary code on the system
  with clamd privileges or cause the application to crash.");

  script_tag(name:"affected", value:"ClamAV before 0.94.1.");

  script_tag(name:"insight", value:"The flaw exists due to an off-by-one error in the function get_unicode_name()
  in libclamav/vba_extract.c");

  script_tag(name:"solution", value:"Upgrade to ClamAV 0.94.1.");

  script_tag(name:"summary", value:"This host has ClamAV installed, and is prone to denial of service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("version_func.inc");

port = get_kb_item( "Services/clamd" );
if( ! port )
  port = 0;

ver = get_kb_item( "ClamAV/remote/Ver" );
if( ! ver ) {
  ver = get_kb_item( "ClamAV/Lin/Ver" );
  if( ! ver ) {
    ver = get_kb_item("ClamAV/Win/Ver");
  }
}

if( ! ver )
  exit( 0 );

if( version_is_less( version:ver, test_version:"0.94.1" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"0.94.1" );
  security_message( port:port, data:report );
}

exit( 0 );