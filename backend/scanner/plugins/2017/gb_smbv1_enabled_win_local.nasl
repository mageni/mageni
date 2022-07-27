###############################################################################
# OpenVAS Vulnerability Test
#
# SMBv1 enabled (Local Windows Check)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810554");
  script_version("2019-05-20T06:24:13+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 06:24:13 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-02-15 13:56:01 +0530 (Wed, 15 Feb 2017)");
  script_name("SMBv1 enabled (Local Windows Check)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_smbv1_server_detect.nasl", "gb_smbv1_client_detect.nasl");
  script_mandatory_keys("smb_v1/enabled");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2696547");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/204279");

  script_tag(name:"summary", value:"The host has enabled SMBv1 for the SMB Client or Server.");

  script_tag(name:"vuldetect", value:"Checks if SMBv1 is enabled for the SMB Client or Server based on the
  information provided by the following two VTs:

  - SMBv1 Client Detection (OID: 1.3.6.1.4.1.25623.1.0.810550)

  - SMBv1 Server Detection (OID: 1.3.6.1.4.1.25623.1.0.810549).");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

if( get_kb_item( "smb_v1/enabled" ) ) {

  if( get_kb_item( "smb_v1_server/enabled" ) )
    report = "- SMBv1 is enabled for the SMB Server";

  if( report )
    report += '\n';

  if( get_kb_item( "smb_v1_client/enabled" ) )
    report += "- SMBv1 is enabled for the SMB Client";

  log_message( port:0, data:report );
}

exit( 0 );