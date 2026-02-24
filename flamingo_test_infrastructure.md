# Flamingo Finance Test Infrastructure Analysis

**Repo investigated:** https://github.com/flamingo-finance/flamingo-contract-staking-n3

---

## Key Finding: `Neo.Compiler.CSharp.UnitTests.Utils` is a LOCAL project — NOT a NuGet package

Flamingo ships the entire Neo compiler test infrastructure as **vendored source code** inside their repository. There is no `.gitmodules` file — all files are committed directly.

### Repository structure

```
flamingo-contract-staking-n3/
├── FLM/                              # FLM token contract
├── Staking/                          # Staking contract
├── UnitStakingTest/                  # Test project (uses TestEngine)
├── UnitTest/                         # FLM unit tests
├── Neo.Compiler.CSharp/              # Neo C# compiler (local copy)
├── Neo.Compiler.CSharp.UnitTests/    # Test utilities (local copy) ← KEY
│   └── Utils/
│       ├── TestEngine.cs
│       ├── TestDataCache.cs
│       └── Extensions.cs
├── Neo.SmartContract.Framework/      # SC framework (local copy)
└── flamingo-contract-staking.sln
```

---

## Test project `.csproj` — `UnitStakingTest/UnitStakingTest.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net5.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="xunit" Version="2.4.1" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.4.3">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
    <PackageReference Include="coverlet.collector" Version="1.3.0">
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
    <PackageReference Include="MSTest.TestFramework" Version="2.2.3" />
    <PackageReference Include="MSTest.TestAdapter" Version="2.2.3" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="16.9.4" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp" Version="3.9.0" />
  </ItemGroup>

  <ItemGroup>
    <!-- LOCAL project reference — not NuGet -->
    <ProjectReference Include="..\Neo.Compiler.CSharp.UnitTests\Neo.Compiler.CSharp.UnitTests.csproj" />
    <ProjectReference Include="..\Neo.SmartContract.Framework\Neo.SmartContract.Framework.csproj">
        <Aliases>scfx</Aliases>
    </ProjectReference>
  </ItemGroup>

</Project>
```

### Dependency chain (all local ProjectReferences)

```
UnitStakingTest.csproj
  └── Neo.Compiler.CSharp.UnitTests.csproj   (local)
        └── Neo.Compiler.CSharp.csproj        (local)
        └── Neo.SmartContract.Framework.csproj (local)
  └── Neo.SmartContract.Framework.csproj      (local)
```

Only test runner packages (`xunit`, `MSTest`, `coverlet`) come from NuGet.

---

## `Neo.Compiler.CSharp.UnitTests/Neo.Compiler.CSharp.UnitTests.csproj`

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net5.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <RootNamespace>Neo.Compiler.CSharp.UnitTests</RootNamespace>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="16.9.4" />
    <PackageReference Include="MSTest.TestAdapter" Version="2.2.3" />
    <PackageReference Include="MSTest.TestFramework" Version="2.2.3" />
    <PackageReference Include="coverlet.collector" Version="3.0.3">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
  </ItemGroup>

  <ItemGroup>
    <Compile Remove="TestClasses\*.cs" />
    <None Include="TestClasses\*.cs">
      <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    </None>
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\Neo.SmartContract.Framework\Neo.SmartContract.Framework.csproj">
        <Aliases>scfx</Aliases>
    </ProjectReference>
    <ProjectReference Include="..\Neo.Compiler.CSharp\Neo.Compiler.CSharp.csproj" />
  </ItemGroup>

</Project>
```

---

## `TestEngine.cs` — Full source

```csharp
extern alias scfx;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Neo.IO;
using Neo.IO.Json;
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.SmartContract;
using Neo.SmartContract.Manifest;
using Neo.SmartContract.Native;
using Neo.VM;
using Neo.VM.Types;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Numerics;

namespace Neo.Compiler.CSharp.UnitTests.Utils
{
    public class TestEngine : ApplicationEngine
    {
        public const long TestGas = 2000_00000000;

        private static readonly List<MetadataReference> references = new();

        public NefFile Nef { get; private set; }
        public JObject Manifest { get; private set; }
        public JObject DebugInfo { get; private set; }

        static TestEngine()
        {
            string coreDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
            references.Add(MetadataReference.CreateFromFile(Path.Combine(coreDir, "System.Runtime.dll")));
            references.Add(MetadataReference.CreateFromFile(Path.Combine(coreDir, "System.Runtime.InteropServices.dll")));
            references.Add(MetadataReference.CreateFromFile(typeof(string).Assembly.Location));
            references.Add(MetadataReference.CreateFromFile(typeof(DisplayNameAttribute).Assembly.Location));
            references.Add(MetadataReference.CreateFromFile(typeof(BigInteger).Assembly.Location));
            // Compiles Neo.SmartContract.Framework from local source at startup
            string folder = Path.GetFullPath("../../../../Neo.SmartContract.Framework/");
            string obj = Path.Combine(folder, "obj");
            IEnumerable<SyntaxTree> st = Directory.EnumerateFiles(folder, "*.cs", SearchOption.AllDirectories)
                .Where(p => !p.StartsWith(obj))
                .OrderBy(p => p)
                .Select(p => CSharpSyntaxTree.ParseText(File.ReadAllText(p), path: p));
            CSharpCompilationOptions options = new(OutputKind.DynamicallyLinkedLibrary);
            CSharpCompilation cr = CSharpCompilation.Create(null, st, references, options);
            cr.Emit("./Neo.SmartContract.Framework.dll");
            references.Add(MetadataReference.CreateFromFile("./Neo.SmartContract.Framework.dll"));
        }

        public TestEngine(TriggerType trigger = TriggerType.Application,
                          IVerifiable verificable = null,
                          DataCache snapshot = null,
                          Block persistingBlock = null)
             : base(trigger, verificable, snapshot, persistingBlock, ProtocolSettings.Default, TestGas)
        {
        }

        public CompilationContext AddEntryScript_Project(string project)
        {
            CompilationContext context = CompilationContext.CompileProject(project, new Options
            {
                AddressVersion = ProtocolSettings.Default.AddressVersion
            });
            if (context.Success)
            {
                Nef = context.CreateExecutable();
                Manifest = context.CreateManifest();
                DebugInfo = context.CreateDebugInformation();
                Reset();
            }
            return context;
        }

        public CompilationContext CompileProject(string project)
        {
            CompilationContext context = CompilationContext.CompileProject(project, new Options
            {
                AddressVersion = ProtocolSettings.Default.AddressVersion
            });
            return context;
        }

        public void Reset()
        {
            this.State = VMState.BREAK;
            this.InvocationStack.Clear();
            while (this.ResultStack.Count > 0) this.ResultStack.Pop();
            if (Nef != null)
            {
                this.LoadScript(Nef.Script);
                var contextState = CurrentContext.GetState<ExecutionContextState>();
                contextState.Contract ??= new ContractState { Nef = Nef };
            }
        }

        public EvaluationStack ExecuteTestCaseStandard(string methodname, params StackItem[] args)
        {
            // Looks up method offset from ABI manifest, pushes args, executes
            var offset = GetMethodEntryOffset(methodname);
            if (offset == -1) throw new Exception("Can't find method : " + methodname);
            var rvcount = GetMethodReturnCount(methodname);
            return ExecuteTestCaseStandard(offset, (ushort)rvcount, Nef, args);
        }
        // ... (rest truncated for brevity)
    }
}
```

---

## `TestDataCache.cs` — Full source

```csharp
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.SmartContract;
using System.Collections.Generic;
using System.Linq;

namespace Neo.Compiler.CSharp.UnitTests.Utils
{
    public class TestDataCache : DataCache
    {
        private readonly Dictionary<StorageKey, StorageItem> dict = new();

        public TestDataCache(Block persistingBlock = null)
        {
            this.DeployNativeContracts(persistingBlock);
        }

        protected override void AddInternal(StorageKey key, StorageItem value) => dict.Add(key, value);
        protected override void DeleteInternal(StorageKey key) => dict.Remove(key);
        protected override bool ContainsInternal(StorageKey key) => dict.ContainsKey(key);
        protected override StorageItem GetInternal(StorageKey key) => dict.TryGetValue(key, out var v) ? v : null;
        protected override StorageItem TryGetInternal(StorageKey key) => dict.TryGetValue(key, out var v) ? v : null;
        protected override void UpdateInternal(StorageKey key, StorageItem value) => dict[key] = value;
        protected override IEnumerable<(StorageKey Key, StorageItem Value)> SeekInternal(byte[] keyOrPrefix, SeekDirection direction)
            => dict.Select(u => (u.Key, u.Value));
    }
}
```

---

## Test initialization pattern (from `StakingTest.cs`)

```csharp
[TestInitialize]
public void Init()
{
    TestDataCache dataCache = new TestDataCache();          // in-memory storage, deploys native contracts
    UInt160 defaultSender = new UInt160(owner);

    engine = new TestEngine(
        TriggerType.Application,
        new DummyVerificable(defaultSender),               // mock tx signer
        snapshot: dataCache,
        persistingBlock: new Block { Header = new Header { Index = 123, ... } }
    );

    // Load contract from local .csproj path
    string path = "../../../../Staking/";
    string file = Directory.GetFiles(path, "*.csproj").FirstOrDefault();
    engine.AddEntryScript_Project(file);                   // compiles + sets as entry

    // Register in snapshot
    engine.Snapshot.ContractAdd(new ContractState()
    {
        Hash = engine.Nef.Script.ToScriptHash(),
        Nef = engine.Nef,
        Manifest = ContractManifest.FromJson(engine.Manifest)
    });
    engine.Snapshot.Commit();
}

// Test method pattern
[TestMethod]
public void TestGetOwner()
{
    engine.Reset();
    var stack = engine.ExecuteTestCaseStandard("getOwner");
    Assert.AreEqual(stack.Pop().GetSpan().ToArray().ToHexString(), owner.ToHexString());
}
```

---

## Summary

| Question | Answer |
|----------|--------|
| Is `Neo.Compiler.CSharp.UnitTests.Utils` a NuGet package? | **No** |
| Is it a local/vendored dependency? | **Yes** — committed source in `Neo.Compiler.CSharp.UnitTests/Utils/` |
| Is it a git submodule? | **No** — no `.gitmodules` file, files committed directly |
| Target framework | `net5.0` |
| Storage injection mechanism | `TestDataCache` passed as `snapshot:` to `TestEngine` constructor |
| Contract loading | `engine.AddEntryScript_Project(path_to_csproj)` |
| Method execution | `engine.ExecuteTestCaseStandard("methodName", args...)` |
| Between tests | `engine.Reset()` to clear VM state |
