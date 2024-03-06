#include <bits/stdc++.h>
using namespace std;
#define ll long long

class RSA
{
private:
    unordered_set<ll> primeSet;
    ll publicKey;
    ll privateKey;
    ll n;

    void primefiller()
    {
        vector<bool> seive(500, true);
        seive[0] = false;
        seive[1] = false;
        for (ll i = 2; i < 500; i++)
        {
            for (ll j = i * 2; j < 500; j += i)
            {
                seive[j] = false;
            }
        }

        for (ll i = 0; i < seive.size(); i++)
        {
            if (seive[i] == true)
            {
                primeSet.insert(i);
            }
        }
    }

    ll getRandomPrime()
    {
        srand(time(0));
        ll k = rand() % primeSet.size();

        auto itr = primeSet.begin();
        while (k--)
        {
            itr++;
        }
        ll ret = *itr;
        primeSet.erase(itr);
        return ret;
    }

    void setkeys()
    {
        ll prime1 = getRandomPrime();
        ll prime2 = getRandomPrime();

        n = prime1 * prime2;
        ll eulersPhi = (prime1 - 1) * (prime2 - 1);

        ll e = 2;
        while (1)
        {
            if (__gcd(e, eulersPhi) == 1)
            {
                break;
            }
            e++;
        }
        publicKey = e;

        ll d = 2;
        while (1)
        {
            if ((d * e) % eulersPhi == 1)
            {
                break;
            }
            d++;
        }
        privateKey = d;
    }

    ll encrypt(double message)
    {
        ll e = publicKey;
        ll encryptedMsg = 1;
        while (e--)
        {
            encryptedMsg *= message;
            encryptedMsg %= n;
        }
        return encryptedMsg;
    }

    ll decrypt(ll encryptedMsg)
    {
        ll d = privateKey;
        ll decryptedMsg = 1;
        while (d--)
        {
            decryptedMsg *= encryptedMsg;
            decryptedMsg %= n;
        }
        return decryptedMsg;
    }

public:
    RSA()
    {
        primefiller();
        setkeys();
    }

    vector<ll> encode(string message)
    {
        vector<ll> form;
        for (auto &letter : message)
        {
            form.push_back(encrypt((ll)letter));
        }
        return form;
    }

    string decode(vector<ll> encoded)
    {
        string s;
        for (auto &num : encoded)
        {
            s += decrypt(num);
        }
        return s;
    }
};

int main()
{
    RSA rsa;

    string message = "My Name is Sai Sreekar";

    cout << "Initial message:\n"
         << message << endl;

    vector<ll> coded = rsa.encode(message);
    cout << "\n\nThe Encoded message:\n";
    for (auto &p : coded)
    {
        cout << p;
    }

    cout << "\n\nThe Decoded message:\n";
    cout << rsa.decode(coded) << endl;
    return 0;
}
