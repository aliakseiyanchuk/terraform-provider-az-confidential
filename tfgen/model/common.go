package model

type GroupDispatch func(comamnd string, kwp ContentWrappingParams, args []string) (SubCommandExecution, error)

type SubCommandExecution func(inputReader InputReader, onlyCiphertext bool) (string, error)

type InputReader func(prompt, fn string, base64Decode bool, multiline bool) ([]byte, error)
