###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_40318.nasl 12668 2018-12-05 13:07:54Z cfischer $
#
# ClamAV 'parseicon()' Denial Of Service Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100656");
  script_version("$Revision: 12668 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 14:07:54 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-1640");
  script_bugtraq_id(40318);
  script_name("ClamAV 'parseicon()' Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_clamav_detect_lin.nasl", "gb_clamav_detect_win.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("ClamAV/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40318");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blobdiff;f=libclamav/pe_icons.c;h=3f1bc5be69d0f9d84e576814d1a3cc6f40c4ff2c;hp=39a714f05968f9e929576bf171dd0eb58bf06bef;hb=7f0e3bbf77382d9782e0189bf80f");
  script_xref(name:"URL", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2031");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1");
  script_xref(name:"URL", value:"http://www.clamav.net/");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2940");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"ClamAV is prone to a vulnerability that attackers can exploit
  to cause denial-of-service conditions.");

  script_tag(name:"affected", value:"ClamAV 0.96 is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/clamd");
if(!port)port = 0;

ver = get_kb_item("ClamAV/remote/Ver");
if(!ver) {
  ver = get_kb_item("ClamAV/Lin/Ver");
  if(!ver) {
    ver = get_kb_item("ClamAV/Win/Ver");
  }
}

if(!ver)exit(0);

if(version_is_less(version:ver, test_version:"0.96.1")){
  security_message(port:port);
}

exit(0);