using System;
using Xunit;
using IIG.PasswordHashingUtils;

namespace XUnitTestProject1
{
    public class UnitTest1
    {
        [Fact]
        public void Test_GetHash()
        {
            string password = "password";

            string hash = PasswordHasher.GetHash(password);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Test_SamePasswordHash()
        {
            string password = "password";
            string same_password = "password";

            string hash = PasswordHasher.GetHash(password);
            string same_hash = PasswordHasher.GetHash(same_password);

            Assert.Equal(hash, same_hash);
        }

        [Fact]
        public void Test_DifferentPasswordHash()
        {
            string password = "password";
            string different_password = "psswrd";

            string hash = PasswordHasher.GetHash(password);
            string different_hash = PasswordHasher.GetHash(different_password);

            Assert.NotEqual(hash, different_hash);
        }

        [Fact]
        public void Test_Password_Is_Null()
        {
            string password = null;
            Assert.Throws<ArgumentNullException>(() => PasswordHasher.GetHash(password));
        }

        [Fact]
        public void Test_Password_Is_Empty()
        {
            string password = "";

            Assert.NotNull(PasswordHasher.GetHash(password));
            Assert.NotEmpty(PasswordHasher.GetHash(password));
        }
        [Fact]
        public void Test_GetHashWithSalt()
        {
            string password = "password";
            string salt = "salt";

            string hash = PasswordHasher.GetHash(password, salt);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Test_GetHashNullSalt()
        {
            string password = "password";
            string salt = null;

            string hash1 = PasswordHasher.GetHash(password, salt);
            string hash2 = PasswordHasher.GetHash(password);

            Assert.NotNull(hash1);
            Assert.NotEmpty(hash1);
            Assert.Equal(hash2, hash1);
        }

        [Fact]
        public void Test_GetHashEmptySalt()
        {
            string password = "password";
            string salt = "";

            string hash1 = PasswordHasher.GetHash(password, salt);
            string hash2 = PasswordHasher.GetHash(password);

            Assert.NotNull(hash1);
            Assert.NotEmpty(hash1);
            Assert.Equal(hash2, hash1);
        }

        [Fact]
        public void Test_DifferentSaltHash()
        {
            string password = "password";
            string salt = "salt";
            string different_salt = "sugar";


            string hash = PasswordHasher.GetHash(password, salt);
            string different_hash = PasswordHasher.GetHash(password, different_salt);

            Assert.NotEqual(hash, different_hash);
        }

        [Fact]
        public void Test_GetHashWithAdlerMod()
        {
            string password = "password";
            string salt = "salt";
            uint adlerMod = 16;

            string hash = PasswordHasher.GetHash(password, salt, adlerMod);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Test_DifferentAdlerModHash()
        {
            string password = "password";
            string salt = "salt";
            uint mod = 16;
            uint different_mod = 17;


            string hash = PasswordHasher.GetHash(password, salt, mod);
            string different_hash = PasswordHasher.GetHash(password, salt, different_mod);

            Assert.NotEqual(hash, different_hash);
        }

        [Fact]
        public void Test_ZeroAdlerModHash()
        {
            string password = "password";
            string salt = "salt";
            uint mod = 0;


            string hash = PasswordHasher.GetHash(password, salt, mod);
            string same_hash = PasswordHasher.GetHash(password, salt);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);

            Assert.Equal(same_hash, hash);
        }

        [Fact]
        public void Test_PasswordWithSpecialSymbols()
        {
            string password = "♠ ♦ ♣ ♥";
            string salt = "salt";
            uint adlerMod = 16;

            string hash = PasswordHasher.GetHash(password, salt, adlerMod);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Test_SaltWithSpecialSymbols()
        {
            string password = "password";
            string salt = "♠ ♦ ♣ ♥";
            uint adlerMod = 16;

            string hash = PasswordHasher.GetHash(password, salt, adlerMod);

            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Test_SpecialAdlerMod()
        {
            string password = "password";
            string salt = "salt";
            uint adlerModMin = uint.MinValue;
            uint adlerModMax = uint.MaxValue;

            string hash1 = PasswordHasher.GetHash(password, salt, adlerModMin);
            string hash2 = PasswordHasher.GetHash(password, salt, adlerModMax);

            Assert.NotNull(hash1);
            Assert.NotEmpty(hash1);
            Assert.NotEqual(password, hash1);

            Assert.NotNull(hash2);
            Assert.NotEmpty(hash2);
            Assert.NotEqual(password, hash2);
        }

        [Fact]
        public void Test_Init()
        {
            string password = "password";
            string salt1 = "salt1";
            string salt2 = "salt2";
            uint adlerMod = 16;

            PasswordHasher.Init(salt1, adlerMod);
            Assert.Equal(PasswordHasher.GetHash(password), PasswordHasher.GetHash(password, salt1, adlerMod));

            Assert.NotEqual(PasswordHasher.GetHash(password), PasswordHasher.GetHash(password, salt2, adlerMod));
        }

        [Fact]
        public void Test_InitSaltNull()
        {
            string password = "password";
            string salt1 = null;
            uint adlerMod = 16;

            PasswordHasher.Init(salt1, adlerMod);
            string hash = PasswordHasher.GetHash(password);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.Equal(hash, PasswordHasher.GetHash(password, salt1, adlerMod));
        }

    }
}
