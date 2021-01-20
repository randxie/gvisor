// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int dirmode_mask = 07777;
constexpr int dirmode_sgid = 02777;
constexpr int dirmode_noexec = 02767;
constexpr int dirmode_nosgid = 00777;

// Sets effective GID and returns a Cleanup that restores the original.
PosixErrorOr<Cleanup> Setegid(gid_t egid) {
  gid_t old_gid = getegid();
  if (setegid(egid) < 0) {
    return PosixError(errno, absl::StrFormat("setegid(%d)", egid));
  }
  return Cleanup(
      [old_gid]() { EXPECT_THAT(setegid(old_gid), SyscallSucceeds()); });
}

// Returns a pair of groups that the user is a member of.
PosixErrorOr<std::pair<gid_t, gid_t>> Groups() {
  // See whether the user is a member of at least 2 groups.
  std::vector<gid_t> groups(64);
  for (; groups.size() <= NGROUPS_MAX; groups.resize(groups.size() * 2)) {
    int ngroups = getgroups(groups.size(), groups.data());
    if (ngroups < 0 && errno == EINVAL) {
      // Need a larger list.
      continue;
    }
    if (ngroups < 0) {
      return PosixError(errno, absl::StrFormat("getgroups(%d, %p)",
                                               groups.size(), groups.data()));
    }
    if (ngroups >= 2) {
      return std::pair<gid_t, gid_t>(groups[0], groups[1]);
    }
    // There aren't enough groups.
    break;
  }

  // If we're root in the root user namespace, we can set our GID to whatever we
  // want. Try that before giving up.
  constexpr gid_t kGID1 = 1111;
  constexpr gid_t kGID2 = 2222;
  auto cleanup1 = Setegid(kGID1);
  if (!cleanup1.ok()) {
    return cleanup1.error();
  }
  auto cleanup2 = Setegid(kGID2);
  if (!cleanup2.ok()) {
    return cleanup2.error();
  }
  return std::pair<gid_t, gid_t>(kGID1, kGID2);
}

// The control test. Files created with a given GID are owned by that group.
TEST(SetgidDirTest, Control) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1 and create a directory.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), 0777), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  ASSERT_EQ(getegid(), groups.first);
  EXPECT_EQ(stats.st_gid, groups.first);

  // Set group to G2, create a file in g1owned, and confirm that G2 owns it.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  ASSERT_EQ(getegid(), groups.second);
  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(g1owned, "g2owned").c_str(), O_CREAT | O_RDWR, 0777),
      SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);
}

// Setgid directories cause created files to inherit GID.
TEST(SetgidDirTest, CreateFile) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_sgid);

  // Set group to G2, create a file, and confirm that G1 owns it.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(g1owned, "g2created").c_str(), O_CREAT | O_RDWR, 0666),
      SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
}

// Setgid directories cause created directories to inherit GID.
TEST(SetgidDirTest, CreateDir) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_sgid);

  // Set group to G2, create a directory, confirm that G1 owns it, and that the
  // setgid bit is enabled.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_THAT(mkdir(g2created.c_str(), 0666), SyscallSucceeds());
  ASSERT_THAT(stat(g2created.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & S_ISGID, S_ISGID);
}

// Setgid directories with group execution disabled still cause GID inheritance.
TEST(SetgidDirTest, NoGroupExec) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_noexec), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_noexec), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_noexec);

  // Set group to G2, create a directory, confirm that G2 owns it, and that the
  // setgid bit is enabled.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_THAT(mkdir(g2created.c_str(), 0666), SyscallSucceeds());
  ASSERT_THAT(stat(g2created.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & S_ISGID, S_ISGID);
}

// Setting the setgid bit on directories with an existing file does not change
// the file's group.
TEST(SetgidDirTest, OldFile) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1 and create a directory.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_nosgid), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_nosgid), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_nosgid);

  // Set group to G2, create a file, confirm that G2 owns it.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(g1owned, "g2created").c_str(), O_CREAT | O_RDWR, 0666),
      SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);

  // Enable setgid.
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());

  // Confirm that the file's group is still G2.
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);
}

// Setting the setgid bit on directories with an existing subdirectory does not
// change the subdirectory's group.
TEST(SetgidDirTest, OldDir) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_nosgid), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_nosgid), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_nosgid);

  // Set group to G2, create a directory, confirm that G2 owns it.
  ASSERT_THAT(setegid(groups.second), SyscallSucceeds());
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_THAT(mkdir(g2created.c_str(), 0666), SyscallSucceeds());
  ASSERT_THAT(stat(g2created.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);

  // Enable setgid.
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_sgid), SyscallSucceeds());

  // Confirm that the file's group is still G2.
  ASSERT_THAT(stat(g2created.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);
}

// Chowning a file clears the setgid and setuid bits.
TEST(SetgidDirTest, ChownFileClears) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_mask), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_mask), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_mask);

  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(g1owned, "newfile").c_str(), O_CREAT | O_RDWR, 0666),
      SyscallSucceeds());
  ASSERT_THAT(fchmod(fd, 0777 | S_ISUID | S_ISGID), SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISUID | S_ISGID);

  // Change the owning group.
  ASSERT_THAT(fchown(fd, -1, groups.second), SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());

  // The setgid and setuid bits should be cleared.
  EXPECT_EQ(stats.st_gid, groups.second);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), 0);
}

// Chowning a file with setgid enabled, but not the group exec bit, does not
// clear the setgid bit. Such files are mandatory locked.
TEST(SetgidDirTest, ChownNoExecFileDoesNotClear) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_noexec), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_noexec), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_noexec);

  int fd;
  ASSERT_THAT(
      fd = open(JoinPath(g1owned, "newdir").c_str(), O_CREAT | O_RDWR, 0666),
      SyscallSucceeds());
  ASSERT_THAT(fchmod(fd, 0766 | S_ISUID | S_ISGID), SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISUID | S_ISGID);

  // Change the owning group.
  ASSERT_THAT(fchown(fd, -1, groups.second), SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());

  // Only the setuid bit is cleared.
  EXPECT_EQ(stats.st_gid, groups.second);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISGID);
}

// Chowning a directory with setgid enabled does not clear the bit.
TEST(SetgidDirTest, ChownDirDoesNotClear) {
  // TODO(b/175325250): Enable when setgid directories are supported.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));
  SKIP_IF(IsRunningWithVFS1());

  // Set group to G1, create a directory, and enable setgid.
  auto groups = ASSERT_NO_ERRNO_AND_VALUE(Groups());
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups.first));
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto g1owned = JoinPath(temp_dir.path(), "g1owned/");
  ASSERT_THAT(mkdir(g1owned.c_str(), dirmode_mask), SyscallSucceeds());
  ASSERT_THAT(chmod(g1owned.c_str(), dirmode_mask), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.first);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_mask);

  // Change the owning group.
  ASSERT_THAT(chown(g1owned.c_str(), -1, groups.second), SyscallSucceeds());

  ASSERT_THAT(stat(g1owned.c_str(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_gid, groups.second);
  EXPECT_EQ(stats.st_mode & dirmode_mask, dirmode_mask);
}

TEST(SetgidDirTest, WriteToFile) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  struct testcase {
    std::string name;
    int mode;
    int result_mode;
  };
  struct testcase testcases[] = {
      {"normal file", 0777, 0777},
      {"setuid", 04777, 00777},
      {"setgid", 02777, 00777},
      {"setuid and setgid", 06777, 00777},
      {"setgid without exec", 02767, 02767},
      {"setuid and setgid without exec", 06767, 02767}};

  for (auto &tc : testcases) {
    auto path = JoinPath(temp_dir.path(), tc.name);
    int fd;
    ASSERT_THAT(fd = open(path.c_str(), O_CREAT | O_RDWR, 0666),
                SyscallSucceeds());
    ASSERT_THAT(fchmod(fd, tc.mode), SyscallSucceeds());
    struct stat stats;
    ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
    EXPECT_EQ(stats.st_mode & dirmode_mask, tc.mode);

    // Writing to the file may clear setuid and setgid bits.
    constexpr char kInput = 'M';
    ASSERT_THAT(write(fd, &kInput, sizeof(kInput)),
                SyscallSucceedsWithValue(sizeof(kInput)));

    ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
    EXPECT_EQ(stats.st_mode & dirmode_mask, tc.result_mode);
  }
}

TEST(SetgidDirTest, TruncateFile) {
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  struct testcase {
    std::string name;
    int mode;
    int result_mode;
  };
  struct testcase testcases[] = {
      {"normal file", 0777, 0777},
      {"setuid", 04777, 00777},
      {"setgid", 02777, 00777},
      {"setuid and setgid", 06777, 00777},
      {"setgid without exec", 02767, 02767},
      {"setuid and setgid without exec", 06767, 02767}};

  for (auto &tc : testcases) {
    auto path = JoinPath(temp_dir.path(), tc.name);
    int fd;
    ASSERT_THAT(fd = open(path.c_str(), O_CREAT | O_RDWR, 0666),
                SyscallSucceeds());
    ASSERT_THAT(fchmod(fd, tc.mode), SyscallSucceeds());
    struct stat stats;
    ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
    EXPECT_EQ(stats.st_mode & dirmode_mask, tc.mode);

    // Truncating the file may clear setuid and setgid bits.
    ASSERT_THAT(ftruncate(fd, 0), SyscallSucceeds());

    ASSERT_THAT(fstat(fd, &stats), SyscallSucceeds());
    EXPECT_EQ(stats.st_mode & dirmode_mask, tc.result_mode);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
