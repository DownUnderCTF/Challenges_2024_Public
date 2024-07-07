import {
  Dispatch,
  SetStateAction,
  useState,
  useRef,
  useEffect,
  RefObject,
  ReactElement,
} from "react";
import * as bigIntConversion from "bigint-conversion";
import katex from "katex";

function Section(content: JSX.Element) {
  return (
    <section>
      <div className="py-5 px-4 mx-auto max-w-screen-md lg:py-3 lg:px-6">
        {content}
      </div>
    </section>
  );
}

function Stage1Directions(mods: number[], rems: number[]) {
  if (mods.length !== rems.length) {
    throw Error("Number of moduli does not equal number of remainders");
  }

  return Section(
    <div className="text-gray-400 sm:text-lg">
      <h2 className="mb-4 text-4xl tracking-tight font-bold text-white">
        Sun Zi's Perfect Math Class{" "}
      </h2>
      <p className="mb-4 font-medium">
        In 200 BC, the Chinese general Han Xin marched into battle with 1500
        soldiers. Afterwards, he could estimate that between 1000 and 1100 of
        them survived the battle, but needed to know exactly how many men he
        had.
      </p>
      <p className="mb-4 font-medium">
        At that moment, Han Xin&apos;s steward came up to his side and said
      </p>
      <blockquote className="p-4 my-4 border-s-4 border-gray-500 bg-gray-800">
        <p className="font-medium leading-relaxed text-white">
          When the soldiers stand {mods[0]} in a row, there are {rems[0]}{" "}
          soldiers left over. When they line up {mods[1]} in a row, there are{" "}
          {rems[1]} soldiers left over. When they line up {mods[2]} in a row,
          there are {rems[2]} soldiers left over.
        </p>
      </blockquote>
      <p className="mb-4 font-medium">
        Upon hearing this, Han Xin knew immediately how many soldiers he had
        remaining.
      </p>
      <p className="font-bold text-white mt-6">
        How many soldiers did Han Xin have remaining?
      </p>
    </div>
  );
}

interface KatexProps {
  texExpression: string;
  displayMode: boolean;
  className: string;
}

function Katex({ texExpression, displayMode, className }: KatexProps) {
  const ref = useRef(null);

  useEffect(
    () =>
      katex.render(texExpression, ref.current!, { displayMode: displayMode }),
    [texExpression, displayMode]
  );

  return <div className={className} ref={ref} />;
}

Katex.defaultProps = {
  className: "katex",
};

function Stage2Directions(
  cts: bigint[],
  ns: bigint[],
  scrollRef: RefObject<HTMLDivElement>
) {
  if (cts.length !== ns.length) {
    throw Error("Number of ciphertexts does not equal number of remainders");
  }

  return Section(
    <div className="text-gray-400 sm:text-lg">
      <p className="mb-4 font-medium">
        The technique Han Xin used is known to us today as the Chinese Remainder
        Theorem. In the language of modern algebra, we can write the problem as
        the system of equations
        <Katex
          displayMode={true}
          texExpression={String.raw`
        \begin{align*}
        x &\equiv 2 \pmod 3\\
        x &\equiv 4 \pmod 5\\
        x &\equiv 5 \pmod 7\\ 
        \end{align*}
        `}
        />
      </p>
      <p className="mb-4 font-medium">
        The notation{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`x \equiv y \pmod n`}
        />{" "}
        means &quot;the remainder of{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`x`}
        />{" "}
        divided by{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`n`}
        />{" "}
        is equal to{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`y`}
        />
        &quot;.
      </p>
      <p className="mb-4 font-medium" ref={scrollRef}>
        This idea of working with &quot;remainders after division&quot;
        underpins many of our building blocks for modern cryptography. One of
        these building blocks is the RSA cryptosystem. Broadly speaking, the RSA
        cryptosystem takes a secret number{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`m`}
        />{" "}
        and turns it into an encrypted number{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`c`}
        />{" "}
        by calculating the value
        <Katex
          displayMode={true}
          texExpression={String.raw`c = m^e \pmod n.`}
        />
      </p>
      <p className="mb-4 font-medium">
        Given only the values of{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`e`}
        />
        ,{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`c`}
        />{" "}
        and{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`n`}
        />
        , it should be impossible for an attacker to recover the secret message.
        However something strange happens when{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`e`}
        />{" "}
        is small and the same message is sent multiple times using different{" "}
        <Katex
          className="inline-flex"
          displayMode={false}
          texExpression={String.raw`n`}
        />
        . Can you recover the hidden message from the three transmissions below?
      </p>
      <p className="mb-4 font-medium">
        <Katex
          displayMode={true}
          texExpression={String.raw`
        \begin{align*}
        c_1 &\equiv m^e \pmod {n_1}\\
        c_2 &\equiv m^e \pmod {n_2}\\
        c_3 &\equiv m^e \pmod {n_3}\\ 
        \end{align*}
        `}
        />{" "}
        where
      </p>
      <div className="break-all p-2.5 text-sm font-mono rounded-lg">
        <p className="mb-3">e = 3</p>
        <p className="mb-3">
        c_1 =  105001824161664003599422656864176455171381720653815905925856548632486703162518989165039084097502312226864233302621924809266126953771761669365659646250634187967109683742983039295269237675751525196938138071285014551966913785883051544245059293702943821571213612968127810604163575545004589035344590577094378024637
        </p>
        <p className="mb-3">
        c_2 =  31631442837619174301627703920800905351561747632091670091370206898569727230073839052473051336225502632628636256671728802750596833679629890303700500900722642779064628589492559614751281751964622696427520120657753178654351971238020964729065716984136077048928869596095134253387969208375978930557763221971977878737
        </p>
        <p className="mb-3">
        c_3 =  64864977037231624991423831965394304787965838591735479931470076118956460041888044329021534008265748308238833071879576193558419510910272917201870797698253331425756509041685848066195410586013190421426307862029999566951239891512032198024716311786896333047799598891440799810584167402219122283692655717691362258659
        </p>
        <p className="mb-3">
        n_1 =  147896270072551360195753454363282299426062485174745759351211846489928910241753224819735285744845837638083944350358908785909584262132415921461693027899236186075383010852224067091477810924118719861660629389172820727449033189259975221664580227157731435894163917841980802021068840549853299166437257181072372761693
        </p>
        <p className="mb-3">
        n_2 =  95979365485314068430194308015982074476106529222534317931594712046922760584774363858267995698339417335986543347292707495833182921439398983540425004105990583813113065124836795470760324876649225576921655233346630422669551713602423987793822459296761403456611062240111812805323779302474406733327110287422659815403
        </p>
        <p className="mb-3">
        n_3 =  95649308318281674792416471616635514342255502211688462925255401503618542159533496090638947784818456347896833168508179425853277740290242297445486511810651365722908240687732315319340403048931123530435501371881740859335793804194315675972192649001074378934213623075830325229416830786633930007188095897620439987817
        </p>
      </div>
    </div>
  );
}

function ModuloReporter(numSoldiers: number, columnWidth: number) {
  const soldiersRemaining = numSoldiers % columnWidth;
  const soldierNoun = soldiersRemaining === 1 ? "soldier" : "soldiers";
  const soldierArticle = soldiersRemaining === 1 ? "is" : "are";

  return (
    <p className="mb-4 text-white text-center sm:text-lg">
      With {numSoldiers} soldiers standing in rows of {columnWidth}, there{" "}
      {soldierArticle} {numSoldiers % columnWidth} {soldierNoun} left over.{" "}
    </p>
  );
}

interface SquareProps {
  value: string;
  bg: string;
}

function Square({ value, bg }: SquareProps) {
  const styles =
    "h-16 w-16 m-2 sm:text-lg text-center text-white font-bold rounded-lg aspect-square cursor-pointer";
  return (
    <div>
      <button className={styles + " " + bg}>{value}</button>
    </div>
  );
}

interface SandBoxProps {
  numSoldiers: number;
  columnWidth: number;
}

function Sandbox({ numSoldiers, columnWidth }: SandBoxProps) {
  const squares = [];
  for (let i = 0; i < numSoldiers; i++) {
    squares.push(i + 1);
  }

  const leftoverThreshold = numSoldiers - (numSoldiers % columnWidth);
  const showThreshold = 3;
  const hideThreshold = 3;

  const matrix = reshape(
    squares.map(function (index) {
      const bg = index <= leftoverThreshold ? "bg-gray-800" : "bg-primary-700";
      return (
        <div className="basis-auto">
          <Square value={index.toString()} bg={bg} />
        </div>
      );
    }),
    columnWidth
  );

  if (showThreshold < matrix.length - showThreshold - hideThreshold) {
    const hi = matrix.length - showThreshold;
    const lo = showThreshold;
    const replacement = (
      <p className="text-white py-6">
        --- {(hi - lo).toString()} rows hidden ---{" "}
      </p>
    );
    matrix.splice(lo, hi - lo, [replacement]);
  }

  return (
    <div className="mx-auto">
      {matrix.map((row) => (
        <div className="flex flex-row justify-center">{row}</div>
      ))}
    </div>
  );
}

function reshape(flat: ReactElement[], width: number): ReactElement[][] {
  const ret: ReactElement[][] = [];

  return flat.reduce(function (matrix, key, index) {
    if (index % width === 0) {
      matrix.push([key]);
    } else {
      matrix[matrix.length - 1].push(key);
    }
    return matrix;
  }, ret);
}

interface NumberSelectorProps<T extends number | bigint> {
  state: T;
  setState: Dispatch<SetStateAction<T>>;
  minValue: T;
  label: string;
  disabled: boolean;
  parseFunc: (v: string) => T;
  invalidBorder: boolean;
  setInvalidBorder: Dispatch<SetStateAction<boolean>>;
}

function NumberSelector<T extends number | bigint>({
  state,
  setState,
  minValue,
  label,
  disabled,
  parseFunc,
  invalidBorder,
  setInvalidBorder,
}: NumberSelectorProps<T>) {
  const [value, setValue] = useState<string>(state.toString());
  return (
    <div className="w-full">
      <label className="block mb-3 text-sm font-medium text-white">
        <p className="mb-1">{label}</p>
        <input
          className={`${
            invalidBorder
              ? "border-2 border-red-400 focus:outline-red-400 focus:outline-1"
              : "border border-gray-600 focus:outline-gray-300 focus:outline-2"
          } focus:outline mb-4 text-sm rounded-lg block w-full p-2.5 bg-gray-700  placeholder-gray-400 text-white  disabled:ring-primary-400 disabled:border-primary-400 disabled:border-2`}
          min={minValue.toString()}
          value={value}
          disabled={disabled}
          onChange={function (e: React.ChangeEvent<HTMLInputElement>) {
            const valueAsNumber = parseFunc(e.target.value);
            setInvalidBorder(false);

            setValue(e.target.value);
            if (valueAsNumber >= minValue) {
              setState(valueAsNumber);
            }
          }}
        />
      </label>
    </div>
  );
}

NumberSelector.defaultProps = {
  disabled: false,
  invalidBorder: false,
  setInvalidBorder: () => {},
};

interface TransitionProps {
  label: string;
  transition: () => void;
  mods: number[];
  rems: number[];
  secondStage: boolean;
}

const parseDecimal = (v: string) => parseInt(v, 10);

function TransitionInput({
  label,
  transition,
  mods,
  rems,
  secondStage,
}: TransitionProps) {
  const [answer, setAnswer] = useState(0);
  const [invalidBorder, setInvalidBorder] = useState(false);

  const handleSubmit = function (e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();

    for (let i = 0; i < mods.length; i++) {
      if (answer % mods[i] !== rems[i] || answer < 1000 || answer > 1100) {
        setInvalidBorder(true);
        return;
      }
    }

    transition();
  };
  return (
    <form onSubmit={handleSubmit} className="mx-4 lg:mx-6">
      <NumberSelector
        state={answer}
        setState={setAnswer}
        minValue={1}
        label={label}
        disabled={secondStage}
        parseFunc={parseDecimal}
        invalidBorder={invalidBorder}
        setInvalidBorder={setInvalidBorder}
      />
      <div className="flex justify-end">
        <button
          type="submit"
          className="items-center px-5 py-2.5 mt-4 sm:mt-6 font-medium text-center text-white bg-primary-700 rounded-lg focus:ring-4 focus:ring-primary-900 hover:bg-primary-900"
        >
          Submit
        </button>
      </div>
    </form>
  );
}

interface LongToBytesProps {
  long: bigint;
}

function LongToBytes({ long }: LongToBytesProps) {
  return (
    <div className="mx-4">
      <label className="block text-sm font-medium text-white">
        <p>Answer decoded into text:</p>
      </label>
      <p className="text-lg text-center text-white font-bold">
        "{bigIntConversion.bigintToText(long)}"
      </p>
    </div>
  );
}

interface FadeSectionProps {
  wantToBeVisible: boolean;
  children: React.ReactNode;
  contentRef: RefObject<HTMLDivElement>;
}

function FadeSection({
  wantToBeVisible,
  children,
  contentRef,
}: FadeSectionProps) {
  const fadeInProps = {
    className: "animate-fade-in",
    onAnimationStart: () =>
      contentRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      }),
  };

  if (wantToBeVisible) {
    return <div {...fadeInProps}>{children}</div>;
  }
}

function App() {
  const [columnWidth, setColumnWidth] = useState(3);
  const [numSoldiers, setNumSoldiers] = useState(10);
  const [secondStage, setSecondStage] = useState(false);
  const [RSAAnswer, setRSAAnswer] = useState(BigInt(0));
  const stage2Ref = useRef(null);

  const mods = [3, 5, 7];
  const rems = [2, 4, 5];

  const cts = [BigInt("1"), BigInt("2"), BigInt("3")];
  const ns = [BigInt("19"), BigInt("21"), BigInt("31")];

  return (
    <div className="max-w-screen-md mx-auto lg:mb-14 mb-10">
      {Stage1Directions(mods, rems)}
      <div className="px-4 lg:px-6">
        <NumberSelector
          state={columnWidth}
          setState={setColumnWidth}
          minValue={1}
          label={"Column Width: "}
          parseFunc={parseDecimal}
        />
        <NumberSelector
          state={numSoldiers}
          setState={setNumSoldiers}
          minValue={1}
          label={"Number of Soldiers: "}
          parseFunc={parseDecimal}
        />
      </div>
      {ModuloReporter(numSoldiers, columnWidth)}
      <Sandbox numSoldiers={numSoldiers} columnWidth={columnWidth} />
      <TransitionInput
        label={"Answer: "}
        transition={() => setSecondStage(true)}
        mods={mods}
        rems={rems}
        secondStage={secondStage}
      />
      <FadeSection wantToBeVisible={secondStage} contentRef={stage2Ref}>
        {Stage2Directions(cts, ns, stage2Ref)}
        <div className="mx-4">
          <NumberSelector<bigint>
            state={RSAAnswer}
            setState={setRSAAnswer}
            minValue={BigInt(1)}
            label={"Answer for value of hidden message m:"}
            parseFunc={BigInt}
          />
        </div>
        <LongToBytes long={RSAAnswer} />
      </FadeSection>
    </div>
  );
}

export default App;
