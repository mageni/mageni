###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SLAD_SFC_verifyonly.nasl 10620 2018-07-25 14:15:31Z cfischer $
#
# Fetch results of SLAD queries from a remote machine
#
# Primary Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Changed for GSHB by:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 DN-Systems GmbH
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96062");
  script_version("$Revision: 10620 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 16:15:31 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-03-04 16:32:59 +0100 (Thu, 04 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SLAD Microsoft (R) Windows (R) Resource Checker run");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright 2010 DN Systems GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "ssh_authorization.nasl");

  script_tag(name:"summary", value:"This script connects to SLAD on a remote host to run
remote the Microsoft (R) Windows (R) Resource Checker.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

exit(66);
